package capsule

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

type staticFetcher map[string][]byte

func (fetcher staticFetcher) Fetch(_ context.Context, url string) ([]byte, error) {
	contents, ok := fetcher[url]
	if !ok {
		return nil, errors.New("feed unavailable")
	}
	return contents, nil
}

func TestRuntimePlanHasCredentialBlindReadOnlyBoundary(t *testing.T) {
	loaded := testProject(t, false)
	loaded.Spec.Image = "localhost:5000/example/capsule@sha256:" + strings.Repeat("a", 64)
	loaded.Spec.InputSHA256 = strings.Repeat("d", 64)
	loaded.Spec.Provenance = "capsule.provenance.json"
	loaded.Spec.SBOM = "bom.cdx.json"
	loaded.Spec.Environment = map[string]string{"APP_ENV": "test"}
	loaded.Spec.WritablePaths = []string{"/workspace/.cache"}
	if err := loaded.Validate(true); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GH_TOKEN", "must-not-cross")
	plan, err := RuntimePlan(loaded, loaded.Spec.Image, nil)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(plan.DockerArgs, "\n")
	for _, required := range []string{
		"--read-only", "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--user=65532:65532", "dst=/source,readonly", "--tmpfs=/workspace:rw,nosuid,nodev,size=1g,mode=1777",
		"--mount=type=volume,dst=/capsule-deps",
		"--env=NODE_PATH=/capsule-deps/node_modules",
		"--env=PATH=/capsule-deps/node_modules/.bin:/usr/local/bin:/usr/bin:/bin",
		"ln -s /capsule-deps/node_modules /workspace/node_modules",
		"--mount=type=volume,dst=/workspace/.cache",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("runtime plan lacks %s:\n%s", required, joined)
		}
	}
	for _, prohibited := range []string{"must-not-cross", "GH_TOKEN", "docker.sock", "--privileged"} {
		if strings.Contains(joined, prohibited) {
			t.Fatalf("runtime plan exposed %s:\n%s", prohibited, joined)
		}
	}
}

func TestRuntimeLayoutResolvesESMSiblingDependency(t *testing.T) {
	loaded := testProject(t, false)
	loaded.Spec.Image = "localhost:5000/example/capsule@sha256:" + strings.Repeat("a", 64)
	loaded.Spec.InputSHA256 = strings.Repeat("d", 64)
	loaded.Spec.Provenance = "capsule.provenance.json"
	loaded.Spec.SBOM = "bom.cdx.json"
	if err := loaded.Validate(true); err != nil {
		t.Fatal(err)
	}
	plan, err := RuntimePlan(loaded, loaded.Spec.Image, []string{"node", "index.mjs"})
	if err != nil {
		t.Fatal(err)
	}

	imageRoot := t.TempDir()
	buildNodeModules := filepath.Join(imageRoot, "workspace", "node_modules")
	writeESMPackageFixture(t, buildNodeModules)
	runtimeDockerfile := runtimeDockerfileContents("capsulectl-build:test")
	destination, err := runtimeDependencyDestination(runtimeDockerfile)
	if err != nil {
		t.Fatal(err)
	}
	if err := copyDirectory(buildNodeModules, filepath.Join(imageRoot, strings.TrimPrefix(destination, "/"))); err != nil {
		t.Fatal(err)
	}

	volumeRoot := t.TempDir()
	if err := copyDirectory(filepath.Join(imageRoot, "capsule-deps"), volumeRoot); err != nil {
		t.Fatal(err)
	}
	runtimeRoot := t.TempDir()
	runtimeDependencies := filepath.Join(runtimeRoot, "capsule-deps")
	if err := copyDirectory(volumeRoot, runtimeDependencies); err != nil {
		t.Fatal(err)
	}
	if err := removeWriteBits(runtimeDependencies); err != nil {
		t.Fatal(err)
	}
	runtimeWorkspace := filepath.Join(runtimeRoot, "workspace")
	defer func() {
		_ = addWriteBits(runtimeDependencies)
	}()
	if err := os.MkdirAll(runtimeWorkspace, 0o777); err != nil {
		t.Fatal(err)
	}
	symlinkTarget, err := runtimeBootstrapSymlinkTarget(plan)
	if err != nil {
		t.Fatal(err)
	}
	mappedTarget := filepath.Join(runtimeRoot, strings.TrimPrefix(symlinkTarget, "/"))
	if err := os.Symlink(mappedTarget, filepath.Join(runtimeWorkspace, "node_modules")); err != nil {
		t.Fatal(err)
	}

	modulePath := filepath.Join(runtimeWorkspace, "node_modules", "package-a", "index.mjs")
	realModulePath, err := filepath.EvalSymlinks(modulePath)
	if err != nil {
		t.Fatalf("runtime package was not reachable through bootstrap symlink: %v", err)
	}
	moduleContents, err := os.ReadFile(realModulePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(moduleContents, []byte(`from "package-b"`)) {
		t.Fatalf("fixture package does not import sibling module: %s", moduleContents)
	}
	manifestContents, err := os.ReadFile(filepath.Join(filepath.Dir(realModulePath), "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(manifestContents, &manifest); err != nil {
		t.Fatal(err)
	}
	if _, ok := manifest.Dependencies["package-b"]; !ok {
		t.Fatalf("fixture package does not import sibling dependency: %s", manifestContents)
	}
	siblingContents, err := resolveESMDependency(realModulePath, "package-b")
	if err != nil {
		t.Fatalf("ESM sibling dependency was not resolved from package realpath %s: %v", realModulePath, err)
	}
	if !bytes.Contains(siblingContents, []byte(`export const sibling = "resolved"`)) {
		t.Fatalf("resolved sibling module has unexpected contents: %s", siblingContents)
	}

	for _, relative := range []string{
		"node_modules",
		"node_modules/package-a",
		"node_modules/package-a/index.mjs",
	} {
		info, err := os.Lstat(filepath.Join(runtimeDependencies, relative))
		if err != nil {
			t.Fatalf("runtime dependency missing %s: %v", relative, err)
		}
		if info.Mode().Perm()&0o222 != 0 {
			t.Fatalf("runtime dependency %s is writable by the non-root runtime user: %o", relative, info.Mode().Perm())
		}
	}
	executableInfo, err := os.Stat(filepath.Join(runtimeDependencies, "node_modules/package-b/bin/cli.mjs"))
	if err != nil {
		t.Fatal(err)
	}
	if executableInfo.Mode().Perm()&0o111 == 0 {
		t.Fatalf("runtime dependency executable bit was not preserved: %o", executableInfo.Mode().Perm())
	}
	linkInfo, err := os.Lstat(filepath.Join(runtimeDependencies, "node_modules/package-b/alias.mjs"))
	if err != nil {
		t.Fatal(err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatal("runtime dependency symlink was not preserved")
	}
}

func TestSpecRejectsMutableImagesCredentialsAndPublicPorts(t *testing.T) {
	loaded := testProject(t, false)
	loaded.Spec.Image = "node:latest"
	if err := loaded.Validate(true); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("mutable image accepted: %v", err)
	}
	loaded.Spec.Image = "sha256:" + strings.Repeat("b", 64)
	loaded.Spec.SBOM = "bom.cdx.json"
	loaded.Spec.InputSHA256 = strings.Repeat("d", 64)
	loaded.Spec.Provenance = "capsule.provenance.json"
	loaded.Spec.Environment = map[string]string{"API_TOKEN": "value"}
	if err := loaded.Validate(true); err == nil || !strings.Contains(err.Error(), "prohibited") {
		t.Fatalf("credential environment accepted: %v", err)
	}
	loaded.Spec.Environment = nil
	loaded.Spec.Network = "bridge"
	loaded.Spec.Ports = []string{"3000:3000"}
	if err := loaded.Validate(true); err == nil || !strings.Contains(err.Error(), "localhost") {
		t.Fatalf("public port accepted: %v", err)
	}
}

func TestIntakeBuildsFromExplicitInputsAndInvalidatesChangedLockfile(t *testing.T) {
	loaded := testProject(t, true)
	feed := staticFetcher{"https://example.test/deny.csv": cleanFeed()}
	image := "sha256:" + strings.Repeat("c", 64)
	var invocations [][]string
	var runtimeDockerfile []byte
	engine := Engine{execute: func(_ context.Context, _ io.Reader, stdout, _ io.Writer, args ...string) error {
		invocations = append(invocations, append([]string(nil), args...))
		for _, arg := range args {
			filename := strings.TrimPrefix(arg, "--file=")
			if filepath.Base(filename) != "Runtime.Dockerfile" {
				continue
			}
			contents, err := os.ReadFile(filename)
			if err != nil {
				t.Fatalf("read generated runtime Dockerfile: %v", err)
			}
			runtimeDockerfile = append([]byte(nil), contents...)
		}
		if len(args) >= 2 && args[0] == "image" && args[1] == "inspect" {
			_, _ = io.WriteString(stdout, image+"\n")
		}
		return nil
	}}
	now := time.Date(2026, 8, 4, 18, 0, 0, 0, time.UTC)
	result, err := Intake(context.Background(), engine, loaded, feed, now, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if result.Image != image || result.Packages != 2 || len(invocations) != 3 {
		t.Fatalf("unexpected intake result: %#v invocations=%#v", result, invocations)
	}
	build := strings.Join(invocations[0], "\n")
	for _, required := range []string{"build", "--pull", "--no-cache", "--network=default", "--build-arg=NPM_CONFIG_MIN_RELEASE_AGE=3", "--build-arg=NPM_CONFIG_ALLOW_GIT=none", "--build-arg=NPM_CONFIG_ALLOW_REMOTE=none", "--build-arg=NPM_CONFIG_SAVE_EXACT=true"} {
		if !strings.Contains(build, required) {
			t.Fatalf("intake build lacks %s: %s", required, build)
		}
	}
	runtimeBuild := strings.Join(invocations[1], "\n")
	for _, required := range []string{"build", "--no-cache", "--network=none", "--tag=capsulectl:", "Runtime.Dockerfile"} {
		if !strings.Contains(runtimeBuild, required) {
			t.Fatalf("runtime image build lacks %s: %s", required, runtimeBuild)
		}
	}
	expectedRuntimeDockerfile := string(runtimeDockerfileContents("capsulectl-build:" + mustInputDigest(t, loaded)[:16]))
	if string(runtimeDockerfile) != expectedRuntimeDockerfile {
		t.Fatalf("unexpected generated runtime Dockerfile:\n%s", runtimeDockerfile)
	}
	state, err := loaded.ReadState()
	if err != nil {
		t.Fatal(err)
	}
	if state.Image != image || state.BuiltAt != "2026-08-04T18:00:00Z" || len(state.Packages) != 2 {
		t.Fatalf("unexpected state: %#v", state)
	}
	bomContents, err := os.ReadFile(result.SBOM)
	if err != nil || !bytes.Contains(bomContents, []byte(`"bomFormat": "CycloneDX"`)) || !bytes.Contains(bomContents, []byte(`"name": "alpha"`)) {
		t.Fatalf("missing deterministic SBOM: %s err=%v", bomContents, err)
	}
	lockfile := filepath.Join(loaded.SourceRoot, "package-lock.json")
	contents, err := os.ReadFile(lockfile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockfile, append(contents, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loaded.ResolveImageAndState(); err == nil || !strings.Contains(err.Error(), "changed after intake") {
		t.Fatalf("changed lockfile did not invalidate capsule: %v", err)
	}
}

func TestPreChangeRuntimeStateRejectedAfterLayoutPolicyBump(t *testing.T) {
	loaded := testProject(t, true)
	image := "sha256:" + strings.Repeat("e", 64)
	oldDigest, err := loaded.inputDigest(intakePolicyVersion - 1)
	if err != nil {
		t.Fatal(err)
	}
	state := State{
		Schema:      SchemaVersion,
		Image:       image,
		InputSHA256: oldDigest,
		BuiltAt:     time.Now().UTC().Format(time.RFC3339),
		Packages:    []Package{{Name: "alpha", Version: "1.2.3"}},
	}
	stateContents, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(loaded.StateFilename(), stateContents, 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	engine := Engine{execute: func(_ context.Context, _ io.Reader, _ io.Writer, _ io.Writer, args ...string) error {
		called = true
		return nil
	}}
	feed := staticFetcher{"https://example.test/deny.csv": cleanFeed()}
	if err := Run(context.Background(), engine, loaded, []string{"node", "--test"}, feed, time.Now(), nil, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "changed after intake") {
		t.Fatalf("pre-change runtime state was accepted: %v", err)
	}
	if called {
		t.Fatal("pre-change runtime state reached Docker execution")
	}

	state.InputSHA256 = mustInputDigest(t, loaded)
	stateContents, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(loaded.StateFilename(), stateContents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), engine, loaded, []string{"node", "--test"}, feed, time.Now(), nil, io.Discard, io.Discard); err != nil {
		t.Fatalf("fresh runtime state was rejected: %v", err)
	}
	if !called {
		t.Fatal("fresh runtime state did not reach Docker execution")
	}
}

func TestRuntimeLayoutWithDocker(t *testing.T) {
	if os.Getenv("CAPSULECTL_REAL_DOCKER_TEST") != "1" {
		t.Skip("set CAPSULECTL_REAL_DOCKER_TEST=1 to run the ephemeral Docker integration")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the real Docker integration runs only on Linux CI")
	}
	engine, err := DiscoverEngine(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			t.Errorf("close Docker engine: %v", err)
		}
	}()

	loaded := testProject(t, true)
	writeDockerESMPackageFixture(t, loaded.SourceRoot)
	loaded.Spec.Intake.Inputs = []string{
		"package.json",
		"package-lock.json",
		"fixture/package-a/package.json",
		"fixture/package-a/index.mjs",
		"fixture/package-b/package.json",
		"fixture/package-b/index.mjs",
		"fixture/package-b/bin/cli.mjs",
	}
	dockerfile := `FROM node@sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d
ARG NPM_CONFIG_MIN_RELEASE_AGE
ARG NPM_CONFIG_ALLOW_GIT
ARG NPM_CONFIG_ALLOW_REMOTE
ARG NPM_CONFIG_SAVE_EXACT
RUN test "$NPM_CONFIG_MIN_RELEASE_AGE" = "3" \
    && test "$NPM_CONFIG_ALLOW_GIT" = "none" \
    && test "$NPM_CONFIG_ALLOW_REMOTE" = "none" \
    && test "$NPM_CONFIG_SAVE_EXACT" = "true"
COPY fixture/package-a /workspace/node_modules/package-a
COPY fixture/package-b /workspace/node_modules/package-b
RUN ln -s index.mjs /workspace/node_modules/package-b/alias.mjs \
    && mkdir -p /workspace/node_modules/.bin \
    && printf '#!/bin/sh\nexec node /workspace/node_modules/package-a/index.mjs\n' > /workspace/node_modules/.bin/capsule-fixture \
    && chmod 755 /workspace/node_modules/.bin/capsule-fixture
`
	if err := os.WriteFile(filepath.Join(loaded.Directory, loaded.Spec.Intake.Dockerfile), []byte(dockerfile), 0o600); err != nil {
		t.Fatal(err)
	}
	feed := staticFetcher{"https://example.test/deny.csv": cleanFeed()}
	if _, err := Intake(context.Background(), engine, loaded, feed, time.Now().UTC(), io.Discard, io.Discard); err != nil {
		t.Fatalf("actual Docker intake failed: %v", err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		var stdout, stderr bytes.Buffer
		if err := Run(context.Background(), engine, loaded, []string{"capsule-fixture"}, feed, time.Now().UTC(), nil, &stdout, &stderr); err != nil {
			t.Fatalf("actual Docker runtime attempt %d failed: %v\nstdout:\n%s\nstderr:\n%s", attempt, err, stdout.String(), stderr.String())
		}
	}
}

func TestFeedBlocksExactMaliciousArtifactBeforeBuild(t *testing.T) {
	loaded := testProject(t, true)
	feed := staticFetcher{"https://example.test/deny.csv": []byte("Ecosystem,Namespace,Name,Version,Artifact\nnpm,,alpha,1.2.3,alpha-1.2.3.tgz\n")}
	called := false
	engine := Engine{execute: func(context.Context, io.Reader, io.Writer, io.Writer, ...string) error {
		called = true
		return nil
	}}
	_, err := Intake(context.Background(), engine, loaded, feed, time.Now(), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "alpha@1.2.3") {
		t.Fatalf("malicious artifact was not rejected: %v", err)
	}
	if called {
		t.Fatal("Docker build started before deny-feed approval")
	}
}

func TestRunRechecksFeedAndExecutesOnlyHardenedPlan(t *testing.T) {
	loaded := testProject(t, true)
	image := "sha256:" + strings.Repeat("d", 64)
	state := State{Schema: 1, Image: image, InputSHA256: mustInputDigest(t, loaded), BuiltAt: time.Now().UTC().Format(time.RFC3339), Packages: []Package{{Name: "alpha", Version: "1.2.3"}}}
	stateContents, _ := json.Marshal(state)
	if err := os.WriteFile(loaded.StateFilename(), stateContents, 0o600); err != nil {
		t.Fatal(err)
	}
	var invocation []string
	engine := Engine{execute: func(_ context.Context, _ io.Reader, _ io.Writer, _ io.Writer, args ...string) error {
		invocation = append([]string(nil), args...)
		return nil
	}}
	if err := Run(context.Background(), engine, loaded, []string{"node", "--test"}, staticFetcher{"https://example.test/deny.csv": cleanFeed()}, time.Now(), nil, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(invocation, "--read-only") || !slices.Contains(invocation, "--network=none") || !slices.Contains(invocation, "node") || !slices.Contains(invocation, "--test") {
		t.Fatalf("unexpected runtime invocation: %#v", invocation)
	}
}

func TestDockerfileRequiresPinnedBasesAndRejectsSecretMounts(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "Dockerfile")
	for contents, expected := range map[string]string{
		"FROM node:latest\n": "pinned",
		"FROM scratch\nRUN --mount=type=secret echo unsafe\n": "secret",
	} {
		if err := os.WriteFile(filename, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := validateDockerfile(filename, "npm"); err == nil || !strings.Contains(err.Error(), expected) {
			t.Fatalf("Dockerfile %q was not rejected for %s: %v", contents, expected, err)
		}
	}
}

func runtimeDependencyDestination(contents []byte) (string, error) {
	marker := "cp -a /workspace/node_modules/. "
	text := string(contents)
	index := strings.Index(text, marker)
	if index < 0 {
		return "", errors.New("runtime Dockerfile does not copy node_modules")
	}
	fields := strings.Fields(text[index+len(marker):])
	if len(fields) == 0 {
		return "", errors.New("runtime Dockerfile copy has no destination")
	}
	return strings.TrimSuffix(strings.TrimSuffix(fields[0], ";"), "/"), nil
}

func runtimeBootstrapSymlinkTarget(plan Plan) (string, error) {
	for _, arg := range plan.DockerArgs {
		for _, line := range strings.Split(arg, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 4 && fields[0] == "ln" && fields[1] == "-s" && fields[3] == "/workspace/node_modules" {
				return fields[2], nil
			}
		}
	}
	return "", errors.New("runtime bootstrap does not link workspace node_modules")
}

func writeESMPackageFixture(t *testing.T, nodeModules string) {
	t.Helper()
	packages := map[string]struct {
		manifest string
		module   string
	}{
		"package-a": {
			manifest: `{"name":"package-a","type":"module","exports":"./index.mjs","dependencies":{"package-b":"1.0.0"}}`,
			module:   `import { sibling } from "package-b"; export const result = sibling;`,
		},
		"package-b": {
			manifest: `{"name":"package-b","type":"module","exports":"./index.mjs"}`,
			module:   `export const sibling = "resolved";`,
		},
	}
	for name, packageContents := range packages {
		packageRoot := filepath.Join(nodeModules, name)
		if err := os.MkdirAll(packageRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(packageRoot, "package.json"), []byte(packageContents.manifest), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(packageRoot, "index.mjs"), []byte(packageContents.module), 0o644); err != nil {
			t.Fatal(err)
		}
		if name == "package-b" {
			binDirectory := filepath.Join(packageRoot, "bin")
			if err := os.MkdirAll(binDirectory, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(binDirectory, "cli.mjs"), []byte("#!/usr/bin/env node\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("index.mjs", filepath.Join(packageRoot, "alias.mjs")); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func writeDockerESMPackageFixture(t *testing.T, sourceRoot string) {
	t.Helper()
	files := map[string]struct {
		contents string
		mode     os.FileMode
	}{
		"fixture/package-a/package.json": {
			contents: `{"name":"package-a","type":"module","exports":"./index.mjs","dependencies":{"package-b":"1.0.0"}}`,
			mode:     0o644,
		},
		"fixture/package-a/index.mjs": {
			contents: `import { stat, writeFile } from "node:fs/promises";
import { sibling } from "package-b";
const packageDirectory = await stat(new URL("./", import.meta.url));
const moduleFile = await stat(new URL("./index.mjs", import.meta.url));
if (packageDirectory.uid !== 0 || packageDirectory.gid !== 0 || moduleFile.uid !== 0 || moduleFile.gid !== 0) {
  throw new Error("dependency ownership was not root");
}
if (sibling !== "resolved") throw new Error("sibling import failed");
try {
  await writeFile(new URL("./write-probe", import.meta.url), "must fail");
  throw new Error("dependency tree is writable");
} catch (error) {
  if (error?.code !== "EACCES" && error?.code !== "EROFS") throw error;
}
`,
			mode: 0o644,
		},
		"fixture/package-b/package.json": {
			contents: `{"name":"package-b","type":"module","exports":"./index.mjs"}`,
			mode:     0o644,
		},
		"fixture/package-b/index.mjs": {
			contents: `import { lstat, stat } from "node:fs/promises";
const alias = await lstat(new URL("./alias.mjs", import.meta.url));
if (!alias.isSymbolicLink()) throw new Error("dependency symlink was not preserved");
const executable = await stat(new URL("./bin/cli.mjs", import.meta.url));
if ((executable.mode & 0o111) === 0) throw new Error("dependency executable bit was not preserved");
export const sibling = "resolved";
`,
			mode: 0o644,
		},
		"fixture/package-b/bin/cli.mjs": {
			contents: "#!/usr/bin/env node\n",
			mode:     0o755,
		},
	}
	for relative, file := range files {
		filename := filepath.Join(sourceRoot, relative)
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(file.contents), file.mode); err != nil {
			t.Fatal(err)
		}
	}
}

func copyDirectory(source, destination string) error {
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("source is not a directory")
	}
	if err := os.MkdirAll(destination, info.Mode().Perm()); err != nil {
		return err
	}
	if err := os.Chmod(destination, info.Mode().Perm()); err != nil {
		return err
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		sourcePath := filepath.Join(source, entry.Name())
		destinationPath := filepath.Join(destination, entry.Name())
		entryInfo, err := os.Lstat(sourcePath)
		if err != nil {
			return err
		}
		if entryInfo.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(sourcePath)
			if err != nil {
				return err
			}
			if err := os.Symlink(link, destinationPath); err != nil {
				return err
			}
			continue
		}
		if entryInfo.IsDir() {
			if err := copyDirectory(sourcePath, destinationPath); err != nil {
				return err
			}
			continue
		}
		contents, err := os.ReadFile(sourcePath)
		if err != nil {
			return err
		}
		if err := os.WriteFile(destinationPath, contents, entryInfo.Mode().Perm()); err != nil {
			return err
		}
		if err := os.Chmod(destinationPath, entryInfo.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}
func removeWriteBits(root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	if info.IsDir() {
		entries, err := os.ReadDir(root)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := removeWriteBits(filepath.Join(root, entry.Name())); err != nil {
				return err
			}
		}
	}
	return os.Chmod(root, info.Mode().Perm()&^0o222)
}

func addWriteBits(root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	if info.IsDir() {
		entries, err := os.ReadDir(root)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := addWriteBits(filepath.Join(root, entry.Name())); err != nil {
				return err
			}
		}
	}
	return os.Chmod(root, info.Mode().Perm()|0o200)
}

func resolveESMDependency(modulePath, specifier string) ([]byte, error) {
	for directory := filepath.Dir(modulePath); ; directory = filepath.Dir(directory) {
		if filepath.Base(directory) != "node_modules" {
			candidate := filepath.Join(directory, "node_modules", specifier)
			manifestContents, err := os.ReadFile(filepath.Join(candidate, "package.json"))
			if err == nil {
				var manifest struct {
					Exports string `json:"exports"`
					Main    string `json:"main"`
				}
				if err := json.Unmarshal(manifestContents, &manifest); err != nil {
					return nil, err
				}
				entrypoint := manifest.Exports
				if entrypoint == "" {
					entrypoint = manifest.Main
				}
				if entrypoint == "" {
					entrypoint = "index.mjs"
				}
				return os.ReadFile(filepath.Join(candidate, entrypoint))
			}
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
	}
	return nil, errors.New("ESM dependency not found")
}

func testProject(t *testing.T, intake bool) LoadedSpec {
	t.Helper()
	root := t.TempDir()
	specDirectory := filepath.Join(root, ".capsule")
	if err := os.MkdirAll(specDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	lock := `{
  "name": "fixture",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "fixture"},
    "node_modules/alpha": {"version": "1.2.3", "integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="},
    "node_modules/@scope/beta": {"name": "@scope/beta", "version": "2.0.0"}
  }
}`
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"fixture","private":true,"packageManager":"npm@12.0.2"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := Spec{
		Schema:                1,
		SourceURI:             "https://github.com/example-org/example",
		Source:                "..",
		Workdir:               "/workspace",
		Network:               "none",
		Command:               []string{"/probe"},
		MinimumReleaseAgeDays: 3,
		DenyFeeds:             []string{"https://example.test/deny.csv"},
	}
	if intake {
		spec.Intake = &IntakeSpec{Dockerfile: "Dockerfile", Inputs: []string{"package.json", "package-lock.json"}, Lockfile: "package-lock.json"}
		dockerfile := "FROM scratch\nARG NPM_CONFIG_MIN_RELEASE_AGE\nARG NPM_CONFIG_ALLOW_GIT\nARG NPM_CONFIG_ALLOW_REMOTE\nARG NPM_CONFIG_SAVE_EXACT\n"
		if err := os.WriteFile(filepath.Join(specDirectory, "Dockerfile"), []byte(dockerfile), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	contents, _ := json.Marshal(spec)
	specFilename := filepath.Join(specDirectory, "capsule.json")
	if err := os.WriteFile(specFilename, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSpec(specFilename)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func cleanFeed() []byte {
	return []byte("Ecosystem,Namespace,Name,Version,Artifact\nnpm,,unrelated,9.9.9,unrelated.tgz\n")
}

func mustInputDigest(t *testing.T, loaded LoadedSpec) string {
	t.Helper()
	digest, err := loaded.InputDigest()
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
