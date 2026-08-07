package capsule

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var npmPackageName = regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)
var exactPackageVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

var dependencySections = []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}

type ResolveRequest struct {
	Package         string
	OutputDirectory string
	Dev             bool
	Remove          bool
}

type ResolveResult struct {
	Schema   int            `json:"schema"`
	Action   string         `json:"action"`
	Package  string         `json:"package"`
	Manifest string         `json:"manifest"`
	Lockfile string         `json:"lockfile"`
	Packages int            `json:"packages"`
	Feeds    []FeedEvidence `json:"feeds"`
}

type resolvedTarget struct {
	Name    string
	Version string
}

func Resolve(ctx context.Context, engine Engine, loaded LoadedSpec, request ResolveRequest, fetcher FeedFetcher, now time.Time, stdout, stderr io.Writer) (ResolveResult, error) {
	if loaded.Spec.Resolver == nil || loaded.Spec.Intake == nil {
		return ResolveResult{}, errors.New("resolver is not configured")
	}
	manager, managerVersion, err := loaded.Spec.Resolver.packageManager()
	if err != nil {
		return ResolveResult{}, err
	}
	target, err := parseResolveTarget(request.Package, request.Remove)
	if err != nil {
		return ResolveResult{}, err
	}
	if request.Dev && request.Remove {
		return ResolveResult{}, errors.New("--dev cannot be combined with --remove")
	}
	manifestRelative := filepath.Join(filepath.Dir(loaded.Spec.Intake.Lockfile), "package.json")
	if filepath.Dir(loaded.Spec.Intake.Lockfile) == "." {
		manifestRelative = "package.json"
	}
	manifestSource, err := secureRegularFile(loaded.SourceRoot, manifestRelative)
	if err != nil {
		return ResolveResult{}, fmt.Errorf("read package manifest: %w", err)
	}
	lockfileSource, lockfileErr := secureRegularFile(loaded.SourceRoot, loaded.Spec.Intake.Lockfile)
	lockfileExists := lockfileErr == nil
	if lockfileErr != nil && !(manager == "bun" && errors.Is(lockfileErr, os.ErrNotExist)) {
		return ResolveResult{}, fmt.Errorf("read package lockfile: %w", lockfileErr)
	}
	manifestBefore, err := os.ReadFile(manifestSource)
	if err != nil {
		return ResolveResult{}, err
	}
	if err := validatePackageManagerManifest(manifestBefore, manager, managerVersion); err != nil {
		return ResolveResult{}, err
	}
	if err := validateManifestPrecondition(manifestBefore, target, request.Dev, request.Remove); err != nil {
		return ResolveResult{}, err
	}
	var packagesBefore []Package
	if lockfileExists {
		packagesBefore, err = ParseDependencyLock(lockfileSource)
		if err != nil {
			return ResolveResult{}, err
		}
	}
	feedCandidates := append([]Package(nil), packagesBefore...)
	if !request.Remove {
		feedCandidates = append(feedCandidates, Package{Name: target.Name, Version: target.Version})
	}
	if _, err := CheckFeeds(ctx, fetcher, loaded.Spec.DenyFeeds, feedCandidates, now); err != nil {
		return ResolveResult{}, err
	}
	absoluteOutput, parent, err := newResolverOutput(request.OutputDirectory)
	if err != nil {
		return ResolveResult{}, err
	}
	stage, err := os.MkdirTemp(parent, ".capsule-resolve-")
	if err != nil {
		return ResolveResult{}, err
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0o700); err != nil {
		return ResolveResult{}, err
	}
	manifestName := "package.json"
	lockfileName := managerLockfile(manager)
	if err := writeResolverInput(filepath.Join(stage, manifestName), manifestBefore); err != nil {
		return ResolveResult{}, err
	}
	if lockfileExists {
		lockfileBefore, readErr := os.ReadFile(lockfileSource)
		if readErr != nil {
			return ResolveResult{}, readErr
		}
		if err := writeResolverInput(filepath.Join(stage, lockfileName), lockfileBefore); err != nil {
			return ResolveResult{}, err
		}
	}
	versionPlan, err := resolverDockerArgs(loaded, stage, "none", []string{manager, "--version"})
	if err != nil {
		return ResolveResult{}, err
	}
	var versionOutput bytes.Buffer
	if err := engine.command(ctx, nil, &versionOutput, stderr, versionPlan...); err != nil {
		return ResolveResult{}, fmt.Errorf("verify resolver %s version: %w", manager, err)
	}
	if actual := strings.TrimSpace(versionOutput.String()); actual != managerVersion {
		return ResolveResult{}, fmt.Errorf("resolver %s version mismatch: expected %s, got %s", manager, managerVersion, actual)
	}
	command := resolverCommand(loaded, manager, target, request.Dev, request.Remove)
	resolvePlan, err := resolverDockerArgs(loaded, stage, "bridge", command)
	if err != nil {
		return ResolveResult{}, err
	}
	if err := engine.command(ctx, nil, stdout, stderr, resolvePlan...); err != nil {
		return ResolveResult{}, fmt.Errorf("resolve %s package: %w", manager, err)
	}
	if manager == "bun" {
		if err := ensureBunTextLock(stage, lockfileName); err != nil {
			return ResolveResult{}, err
		}
	}
	if err := validateResolverStage(stage, lockfileName); err != nil {
		return ResolveResult{}, err
	}
	manifestCandidate := filepath.Join(stage, manifestName)
	lockfileCandidate := filepath.Join(stage, lockfileName)
	manifestAfter, err := os.ReadFile(manifestCandidate)
	if err != nil {
		return ResolveResult{}, err
	}
	if err := validateManifestMutation(manifestBefore, manifestAfter, target, request.Dev, request.Remove); err != nil {
		return ResolveResult{}, err
	}
	packagesAfter, err := ParseDependencyLock(lockfileCandidate)
	if err != nil {
		return ResolveResult{}, err
	}
	if !request.Remove && !containsPackage(packagesAfter, target) {
		return ResolveResult{}, fmt.Errorf("resolved lockfile does not contain %s@%s", target.Name, target.Version)
	}
	feeds, err := CheckFeeds(ctx, fetcher, loaded.Spec.DenyFeeds, packagesAfter, now)
	if err != nil {
		return ResolveResult{}, err
	}
	if err := os.Rename(stage, absoluteOutput); err != nil {
		return ResolveResult{}, fmt.Errorf("commit resolver output: %w", err)
	}
	action := "add"
	packageValue := target.Name + "@" + target.Version
	if request.Remove {
		action = "remove"
		packageValue = target.Name
	}
	return ResolveResult{
		Schema:   SchemaVersion,
		Action:   action,
		Package:  packageValue,
		Manifest: filepath.Join(absoluteOutput, manifestName),
		Lockfile: filepath.Join(absoluteOutput, lockfileName),
		Packages: len(packagesAfter),
		Feeds:    feeds,
	}, nil
}

func parseResolveTarget(value string, remove bool) (resolvedTarget, error) {
	if remove {
		if !npmPackageName.MatchString(value) {
			return resolvedTarget{}, errors.New("--package must be an exact npm package name for removal")
		}
		return resolvedTarget{Name: value}, nil
	}
	separator := strings.LastIndex(value, "@")
	if separator <= 0 {
		return resolvedTarget{}, errors.New("--package must be name@exact-version")
	}
	name, version := value[:separator], value[separator+1:]
	if !npmPackageName.MatchString(name) || !exactPackageVersion.MatchString(version) {
		return resolvedTarget{}, errors.New("--package must be a valid npm name with an exact semantic version")
	}
	return resolvedTarget{Name: name, Version: version}, nil
}

func newResolverOutput(outputDirectory string) (string, string, error) {
	if outputDirectory == "" {
		return "", "", errors.New("resolver output directory is required")
	}
	absolute, err := filepath.Abs(outputDirectory)
	if err != nil {
		return "", "", err
	}
	if _, err := os.Lstat(absolute); err == nil {
		return "", "", fmt.Errorf("resolver output already exists: %s", absolute)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", "", fmt.Errorf("resolve output parent: %w", err)
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() {
		return "", "", errors.New("resolver output parent must be an existing directory")
	}
	return filepath.Join(parent, filepath.Base(absolute)), parent, nil
}

func writeResolverInput(filename string, contents []byte) error {
	if err := os.WriteFile(filename, contents, 0o600); err != nil {
		return err
	}
	return nil
}

func resolverDockerArgs(loaded LoadedSpec, stage, network string, command []string) ([]string, error) {
	if strings.Contains(stage, ",") {
		return nil, errors.New("resolver path containing a comma is unsupported")
	}
	pullPolicy := "--pull=always"
	if strings.HasPrefix(loaded.Spec.Resolver.Image, "sha256:") {
		pullPolicy = "--pull=never"
	}
	args := []string{
		"run", "--rm", pullPolicy, "--read-only",
		"--network=" + network,
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--pids-limit=256",
		"--memory=2g",
		"--cpus=2",
		"--user=" + strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()),
		"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=512m",
		"--mount=type=bind,src=" + stage + ",dst=/workspace",
		"--workdir=/workspace",
		"--env=HOME=/tmp/home",
		loaded.Spec.Resolver.Image,
	}
	return append(args, command...), nil
}

func resolverNPMCommand(loaded LoadedSpec, target resolvedTarget, dev, remove bool) []string {
	action := "install"
	packageValue := target.Name + "@" + target.Version
	if remove {
		action = "uninstall"
		packageValue = target.Name
	}
	command := []string{
		"npm", action, packageValue,
		"--package-lock-only=true",
		"--ignore-scripts=true",
		"--save-exact=true",
		"--audit=false",
		"--fund=false",
		"--bin-links=false",
		"--allow-directory=none",
		"--allow-file=none",
		"--allow-git=none",
		"--allow-remote=none",
		"--min-release-age=" + strconv.Itoa(loaded.Spec.MinimumReleaseAgeDays),
		"--registry=https://registry.npmjs.org/",
		"--cache=/tmp/npm-cache",
		"--workspaces=false",
		"--loglevel=warn",
	}
	if !remove {
		if dev {
			command = append(command, "--save-dev=true")
		} else {
			command = append(command, "--save-prod=true")
		}
	}
	return command
}

func resolverCommand(loaded LoadedSpec, manager string, target resolvedTarget, dev, remove bool) []string {
	if manager == "bun" {
		action := "add"
		packageValue := target.Name + "@" + target.Version
		if remove {
			action = "remove"
			packageValue = target.Name
		}
		command := []string{
			"bun", action, packageValue,
			"--lockfile-only",
			"--ignore-scripts",
			"--exact",
			"--minimum-release-age=" + strconv.Itoa(loaded.Spec.MinimumReleaseAgeDays*24*60*60),
			"--registry=https://registry.npmjs.org/",
			"--cache-dir=/tmp/bun-cache",
			"--no-progress",
			"--no-summary",
		}
		if dev && !remove {
			command = append(command, "--dev")
		}
		return command
	}
	return resolverNPMCommand(loaded, target, dev, remove)
}

func ensureBunTextLock(stage, lockfileName string) error {
	lockfile := filepath.Join(stage, lockfileName)
	if _, err := os.Lstat(lockfile); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	manifestContents, err := os.ReadFile(filepath.Join(stage, "package.json"))
	if err != nil {
		return err
	}
	manifest, err := decodeJSONObject(manifestContents)
	if err != nil {
		return err
	}
	for _, section := range dependencySections {
		if dependencies, ok := manifest[section].(map[string]any); ok && len(dependencies) > 0 {
			return errors.New("Bun resolver did not produce bun.lock for a non-empty dependency graph")
		}
	}
	workspace := map[string]any{}
	if name, ok := manifest["name"].(string); ok && name != "" {
		workspace["name"] = name
	}
	lock := map[string]any{
		"lockfileVersion": 1,
		"configVersion":   1,
		"workspaces":      map[string]any{"": workspace},
		"packages":        map[string]any{},
	}
	contents, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	return writeResolverInput(lockfile, append(contents, '\n'))
}

func validateResolverStage(stage, lockfileName string) error {
	entries, err := os.ReadDir(stage)
	if err != nil {
		return err
	}
	if len(entries) != 2 {
		return errors.New("resolver produced unexpected output files")
	}
	for _, entry := range entries {
		if entry.Name() != "package.json" && entry.Name() != lockfileName {
			return fmt.Errorf("resolver produced unexpected output: %s", entry.Name())
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("resolver output is not a regular file: %s", entry.Name())
		}
	}
	return nil
}

func validateManifestPrecondition(contents []byte, target resolvedTarget, dev, remove bool) error {
	manifest, err := decodeJSONObject(contents)
	if err != nil {
		return err
	}
	locations := manifestDependencyLocations(manifest, target.Name)
	if remove {
		if len(locations) == 0 {
			return fmt.Errorf("package is not a direct dependency: %s", target.Name)
		}
		return nil
	}
	if len(locations) != 0 {
		return fmt.Errorf("package is already a direct dependency in %s", strings.Join(locations, ", "))
	}
	_ = dev
	return nil
}

func validateManifestMutation(before, after []byte, target resolvedTarget, dev, remove bool) error {
	expected, err := decodeJSONObject(before)
	if err != nil {
		return err
	}
	actual, err := decodeJSONObject(after)
	if err != nil {
		return err
	}
	if remove {
		for _, section := range dependencySections {
			removeManifestDependency(expected, section, target.Name)
		}
	} else {
		section := "dependencies"
		if dev {
			section = "devDependencies"
		}
		dependencies, ok := expected[section].(map[string]any)
		if !ok {
			dependencies = map[string]any{}
			expected[section] = dependencies
		}
		dependencies[target.Name] = target.Version
	}
	normalizeEmptyDependencySections(expected)
	normalizeEmptyDependencySections(actual)
	if !reflect.DeepEqual(expected, actual) {
		return errors.New("resolver changed package.json beyond the requested dependency")
	}
	return nil
}

func decodeJSONObject(contents []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode package.json: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode package.json: trailing JSON value")
	}
	if value == nil {
		return nil, errors.New("package.json must contain an object")
	}
	return value, nil
}

func validatePackageManagerManifest(contents []byte, manager, version string) error {
	manifest, err := decodeJSONObject(contents)
	if err != nil {
		return err
	}
	actual, _ := manifest["packageManager"].(string)
	expected := manager + "@" + version
	if actual != expected {
		return fmt.Errorf("package.json packageManager must be exactly %q", expected)
	}
	if manager == "bun" {
		if _, present := manifest["trustedDependencies"]; !present {
			return errors.New("Bun package.json must declare trustedDependencies explicitly")
		}
		if _, ok := manifest["trustedDependencies"].([]any); !ok {
			return errors.New("Bun package.json trustedDependencies must be an array")
		}
	}
	return nil
}

func manifestDependencyLocations(manifest map[string]any, name string) []string {
	var locations []string
	for _, section := range dependencySections {
		dependencies, ok := manifest[section].(map[string]any)
		if !ok {
			continue
		}
		if _, ok := dependencies[name]; ok {
			locations = append(locations, section)
		}
	}
	return locations
}

func removeManifestDependency(manifest map[string]any, section, name string) {
	dependencies, ok := manifest[section].(map[string]any)
	if !ok {
		return
	}
	delete(dependencies, name)
}

func normalizeEmptyDependencySections(manifest map[string]any) {
	for _, section := range dependencySections {
		dependencies, ok := manifest[section].(map[string]any)
		if ok && len(dependencies) == 0 {
			delete(manifest, section)
		}
	}
}

func containsPackage(packages []Package, target resolvedTarget) bool {
	for _, pkg := range packages {
		if pkg.Name == target.Name && pkg.Version == target.Version {
			return true
		}
	}
	return false
}
