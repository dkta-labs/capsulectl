package capsule

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type Engine struct {
	Binary  string
	Host    string
	Home    string
	execute func(context.Context, io.Reader, io.Writer, io.Writer, ...string) error
}

type CommandError struct {
	Code int
	Err  error
}

func (err CommandError) Error() string { return err.Err.Error() }
func (err CommandError) Unwrap() error { return err.Err }

type Plan struct {
	Schema      int      `json:"schema"`
	Image       string   `json:"image"`
	Source      string   `json:"source"`
	InputSHA256 string   `json:"inputSHA256,omitempty"`
	DockerArgs  []string `json:"dockerArgs"`
}

type CheckResult struct {
	Schema   int            `json:"schema"`
	Image    string         `json:"image"`
	Packages int            `json:"packages"`
	Feeds    []FeedEvidence `json:"feeds"`
}

type IntakeResult struct {
	Schema      int            `json:"schema"`
	Image       string         `json:"image"`
	InputSHA256 string         `json:"inputSHA256"`
	Packages    int            `json:"packages"`
	SBOM        string         `json:"sbom"`
	State       string         `json:"state"`
	Feeds       []FeedEvidence `json:"feeds"`
}

func DiscoverEngine(ctx context.Context) (Engine, error) {
	binary, err := exec.LookPath("docker")
	if err != nil {
		return Engine{}, errors.New("docker CLI is required")
	}
	host := os.Getenv("DOCKER_HOST")
	if host == "" {
		command := exec.CommandContext(ctx, binary, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
		output, err := command.Output()
		if err != nil {
			return Engine{}, fmt.Errorf("resolve Docker context: %w", err)
		}
		host = strings.TrimSpace(string(output))
	}
	if !strings.HasPrefix(host, "unix://") {
		return Engine{}, errors.New("capsule engine must use a local Unix socket")
	}
	socket := strings.TrimPrefix(host, "unix://")
	if runtime.GOOS == "darwin" && !strings.Contains(socket, string(filepath.Separator)+".colima"+string(filepath.Separator)) {
		return Engine{}, errors.New("macOS capsule intake requires a Colima VM Docker context")
	}
	if runtime.GOOS == "linux" && os.Getenv("GITHUB_ACTIONS") != "true" && os.Getenv("CAPSULECTL_EPHEMERAL_CI") != "1" {
		return Engine{}, errors.New("Linux capsule use requires an ephemeral CI runner")
	}
	home, err := os.MkdirTemp("", "capsulectl-engine-")
	if err != nil {
		return Engine{}, err
	}
	if err := os.Chmod(home, 0o700); err != nil {
		os.RemoveAll(home)
		return Engine{}, err
	}
	return Engine{Binary: binary, Host: host, Home: home}, nil
}

func (engine Engine) Close() error {
	if engine.Home == "" {
		return nil
	}
	return os.RemoveAll(engine.Home)
}

func (engine Engine) environment() []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + engine.Home,
		"TMPDIR=" + engine.Home,
		"DOCKER_CONFIG=" + engine.Home,
		"DOCKER_HOST=" + engine.Host,
	}
}

func (engine Engine) command(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) error {
	if engine.execute != nil {
		return engine.execute(ctx, stdin, stdout, stderr, args...)
	}
	command := exec.CommandContext(ctx, engine.Binary, args...)
	command.Env = engine.environment()
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return CommandError{Code: exitError.ExitCode(), Err: err}
		}
		return err
	}
	return nil
}

func RuntimePlan(loaded LoadedSpec, image string, command []string) (Plan, error) {
	return runtimePlanForSource(loaded, image, command, loaded.SourceRoot)
}

func runtimePlanForSource(loaded LoadedSpec, image string, command []string, sourceRoot string) (Plan, error) {
	if !digestReference.MatchString(image) {
		return Plan{}, errors.New("runtime image is not digest-pinned")
	}
	if strings.Contains(sourceRoot, ",") {
		return Plan{}, errors.New("staged source path containing a comma is unsupported by the hardened mount form")
	}
	args := []string{
		"run", "--rm", "--read-only",
		"--network=" + loaded.Spec.Network,
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--pids-limit=256",
		"--memory=2g",
		"--cpus=2",
		"--user=65532:65532",
		"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=256m",
		"--tmpfs=/home/capsule:rw,noexec,nosuid,nodev,size=64m",
		"--tmpfs=/workspace:rw,nosuid,nodev,size=1g,mode=1777",
		"--mount=type=bind,src=" + sourceRoot + ",dst=/source,readonly",
		"--mount=type=volume,dst=/capsule-deps",
		"--workdir=/",
		"--env=HOME=/home/capsule",
		"--env=NODE_PATH=/capsule-deps",
		"--env=PATH=/capsule-deps/.bin:/usr/local/bin:/usr/bin:/bin",
	}
	for _, path := range loaded.Spec.WritablePaths {
		if path == "/workspace/node_modules" {
			continue
		}
		if strings.Contains(path, ",") {
			return Plan{}, fmt.Errorf("writable path containing a comma is unsupported: %s", path)
		}
		args = append(args, "--mount=type=volume,dst="+path)
	}
	ports := append([]string(nil), loaded.Spec.Ports...)
	sort.Strings(ports)
	for _, port := range ports {
		args = append(args, "--publish="+port)
	}
	environment := make([]string, 0, len(loaded.Spec.Environment))
	for name := range loaded.Spec.Environment {
		environment = append(environment, name)
	}
	sort.Strings(environment)
	for _, name := range environment {
		args = append(args, "--env="+name+"="+loaded.Spec.Environment[name])
	}
	args = append(args, image)
	if len(command) == 0 {
		command = loaded.Spec.Command
	}
	const bootstrap = `set -eu
cp -R /source/. /workspace/
rm -rf /workspace/.git /workspace/node_modules
ln -s /capsule-deps /workspace/node_modules
cd "$1"
shift
exec "$@"`
	args = append(args, "/bin/sh", "-c", bootstrap, "capsule-init", loaded.Spec.Workdir)
	args = append(args, command...)
	return Plan{Schema: SchemaVersion, Image: image, Source: sourceRoot, DockerArgs: args}, nil
}

func Run(ctx context.Context, engine Engine, loaded LoadedSpec, command []string, fetcher FeedFetcher, now time.Time, stdin io.Reader, stdout, stderr io.Writer) error {
	image, state, err := loaded.ResolveImageAndState()
	if err != nil {
		return err
	}
	packages, err := loaded.PackagesForImage(state)
	if err != nil {
		return err
	}
	if _, err := CheckFeeds(ctx, fetcher, loaded.Spec.DenyFeeds, packages, now); err != nil {
		return err
	}
	stagedSource, err := prepareRuntimeSource(loaded.SourceRoot)
	if err != nil {
		return err
	}
	defer os.RemoveAll(stagedSource)
	plan, err := runtimePlanForSource(loaded, image, command, stagedSource)
	if err != nil {
		return err
	}
	return engine.command(ctx, stdin, stdout, stderr, plan.DockerArgs...)
}

func Check(ctx context.Context, loaded LoadedSpec, fetcher FeedFetcher, now time.Time) (CheckResult, error) {
	image, state, err := loaded.ResolveImageAndState()
	if err != nil {
		return CheckResult{}, err
	}
	packages, err := loaded.PackagesForImage(state)
	if err != nil {
		return CheckResult{}, err
	}
	feeds, err := CheckFeeds(ctx, fetcher, loaded.Spec.DenyFeeds, packages, now)
	if err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Schema: SchemaVersion, Image: image, Packages: len(packages), Feeds: feeds}, nil
}

func Intake(ctx context.Context, engine Engine, loaded LoadedSpec, fetcher FeedFetcher, now time.Time, stdout, stderr io.Writer) (IntakeResult, error) {
	if loaded.Spec.Intake == nil {
		return IntakeResult{}, errors.New("intake is not configured")
	}
	if err := validateDockerfile(filepath.Join(loaded.Directory, loaded.Spec.Intake.Dockerfile)); err != nil {
		return IntakeResult{}, err
	}
	inputDigest, err := loaded.InputDigest()
	if err != nil {
		return IntakeResult{}, err
	}
	lockfile, err := secureRegularFile(loaded.SourceRoot, loaded.Spec.Intake.Lockfile)
	if err != nil {
		return IntakeResult{}, err
	}
	packages, err := ParsePackageLock(lockfile)
	if err != nil {
		return IntakeResult{}, err
	}
	feeds, err := CheckFeeds(ctx, fetcher, loaded.Spec.DenyFeeds, packages, now)
	if err != nil {
		return IntakeResult{}, err
	}
	stage, err := os.MkdirTemp("", "capsulectl-context-")
	if err != nil {
		return IntakeResult{}, err
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0o700); err != nil {
		return IntakeResult{}, err
	}
	for _, relative := range loaded.Spec.Intake.Inputs {
		source, err := secureRegularFile(loaded.SourceRoot, relative)
		if err != nil {
			return IntakeResult{}, err
		}
		target := filepath.Join(stage, relative)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return IntakeResult{}, err
		}
		contents, err := os.ReadFile(source)
		if err != nil {
			return IntakeResult{}, err
		}
		if err := os.WriteFile(target, contents, 0o600); err != nil {
			return IntakeResult{}, err
		}
	}
	dockerfileContents, err := os.ReadFile(filepath.Join(loaded.Directory, loaded.Spec.Intake.Dockerfile))
	if err != nil {
		return IntakeResult{}, err
	}
	if err := os.WriteFile(filepath.Join(stage, "Dockerfile"), dockerfileContents, 0o600); err != nil {
		return IntakeResult{}, err
	}
	buildTag := "capsulectl-build:" + inputDigest[:16]
	tag := "capsulectl:" + inputDigest[:16]
	buildArgs := []string{
		"build", "--pull", "--no-cache", "--network=default",
		fmt.Sprintf("--build-arg=NPM_CONFIG_MIN_RELEASE_AGE=%d", loaded.Spec.MinimumReleaseAgeDays),
		"--build-arg=NPM_CONFIG_ALLOW_GIT=none",
		"--build-arg=NPM_CONFIG_ALLOW_REMOTE=none",
		"--build-arg=NPM_CONFIG_SAVE_EXACT=true",
		"--tag=" + buildTag,
		"--file=" + filepath.Join(stage, "Dockerfile"),
		stage,
	}
	if err := engine.command(ctx, nil, stdout, stderr, buildArgs...); err != nil {
		return IntakeResult{}, fmt.Errorf("capsule build failed: %w", err)
	}
	runtimeDockerfile := []byte("FROM " + buildTag + "\nUSER 0:0\nRUN mkdir -p /capsule-deps && if [ -d /workspace/node_modules ]; then cp -a /workspace/node_modules/. /capsule-deps/; fi\n")
	runtimeDockerfileName := filepath.Join(stage, "Runtime.Dockerfile")
	if err := os.WriteFile(runtimeDockerfileName, runtimeDockerfile, 0o600); err != nil {
		return IntakeResult{}, err
	}
	runtimeBuildArgs := []string{
		"build", "--no-cache", "--network=none",
		"--tag=" + tag,
		"--file=" + runtimeDockerfileName,
		stage,
	}
	if err := engine.command(ctx, nil, stdout, stderr, runtimeBuildArgs...); err != nil {
		return IntakeResult{}, fmt.Errorf("finalize capsule runtime image: %w", err)
	}
	var inspect bytes.Buffer
	if err := engine.command(ctx, nil, &inspect, stderr, "image", "inspect", "--format={{.Id}}", tag); err != nil {
		return IntakeResult{}, fmt.Errorf("inspect capsule image: %w", err)
	}
	image := strings.TrimSpace(inspect.String())
	if !digestReference.MatchString(image) {
		return IntakeResult{}, fmt.Errorf("Docker returned a non-immutable image ID: %q", image)
	}
	sbom := filepath.Join(loaded.Directory, "intake.cdx.json")
	if err := WriteCycloneDX(sbom, packages); err != nil {
		return IntakeResult{}, err
	}
	state := State{
		Schema:      SchemaVersion,
		Image:       image,
		InputSHA256: inputDigest,
		BuiltAt:     now.UTC().Format(time.RFC3339),
		Packages:    packages,
		Feeds:       feeds,
	}
	stateContents, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return IntakeResult{}, err
	}
	stateContents = append(stateContents, '\n')
	if err := atomicWrite(loaded.StateFilename(), stateContents, 0o600); err != nil {
		return IntakeResult{}, err
	}
	return IntakeResult{Schema: SchemaVersion, Image: image, InputSHA256: inputDigest, Packages: len(packages), SBOM: sbom, State: loaded.StateFilename(), Feeds: feeds}, nil
}

func validateDockerfile(filename string) error {
	info, err := os.Lstat(filename)
	if err != nil {
		return fmt.Errorf("read intake Dockerfile: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return errors.New("intake Dockerfile must be a regular file no larger than 1 MiB")
	}
	contents, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	lower := strings.ToLower(string(contents))
	if strings.Contains(lower, "--mount=type=secret") || strings.Contains(lower, "--mount=type=ssh") {
		return errors.New("intake Dockerfile cannot request secret or SSH mounts")
	}
	fromCount := 0
	requiredArgs := map[string]bool{
		"NPM_CONFIG_MIN_RELEASE_AGE": false,
		"NPM_CONFIG_ALLOW_GIT":       false,
		"NPM_CONFIG_ALLOW_REMOTE":    false,
		"NPM_CONFIG_SAVE_EXACT":      false,
	}
	for _, rawLine := range strings.Split(string(contents), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return fmt.Errorf("invalid Dockerfile instruction: %s", line)
		}
		if strings.EqualFold(fields[0], "ARG") {
			name := strings.SplitN(fields[1], "=", 2)[0]
			if _, required := requiredArgs[name]; required {
				requiredArgs[name] = true
			}
			continue
		}
		if !strings.EqualFold(fields[0], "FROM") {
			continue
		}
		fromCount++
		index := 1
		for index < len(fields) && strings.HasPrefix(fields[index], "--") {
			index++
		}
		if index >= len(fields) {
			return errors.New("invalid FROM instruction")
		}
		base := fields[index]
		if base != "scratch" && !regexpDigestBase(base) {
			return fmt.Errorf("every base image must be pinned by sha256 digest: %s", base)
		}
	}
	if fromCount == 0 {
		return errors.New("intake Dockerfile has no FROM instruction")
	}
	for name, present := range requiredArgs {
		if !present {
			return fmt.Errorf("intake Dockerfile must declare ARG %s", name)
		}
	}
	return nil
}

func regexpDigestBase(base string) bool {
	parts := strings.Split(base, "@")
	return len(parts) == 2 && parts[0] != "" && strings.HasPrefix(parts[1], "sha256:") && len(strings.TrimPrefix(parts[1], "sha256:")) == 64 && allLowerHex(strings.TrimPrefix(parts[1], "sha256:"))
}

func allLowerHex(value string) bool {
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}
