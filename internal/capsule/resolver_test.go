package capsule

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestResolveRunsCredentialBlindAndReturnsOnlyCandidateFiles(t *testing.T) {
	loaded := resolverProject(t)
	manifestFilename := filepath.Join(loaded.SourceRoot, "package.json")
	manifest := `{"name":"fixture","private":true,"scripts":{"preinstall":"touch /workspace/owned"}}`
	if err := os.WriteFile(manifestFilename, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NPM_TOKEN", "must-not-cross")
	var invocations [][]string
	engine := Engine{execute: func(_ context.Context, _ io.Reader, stdout, _ io.Writer, args ...string) error {
		invocations = append(invocations, append([]string(nil), args...))
		joined := strings.Join(args, "\n")
		if strings.HasSuffix(joined, "npm\n--version") {
			_, _ = io.WriteString(stdout, "12.0.2\n")
			return nil
		}
		stage := resolverStageFromArgs(t, args)
		addDependencyToResolverFixture(t, stage, "gamma", "3.2.1")
		return nil
	}}
	output := filepath.Join(t.TempDir(), "candidate")
	result, err := Resolve(context.Background(), engine, loaded, ResolveRequest{
		Package:         "gamma@3.2.1",
		OutputDirectory: output,
	}, staticFetcher{"https://example.test/deny.csv": cleanFeed()}, time.Date(2026, 8, 4, 20, 0, 0, 0, time.UTC), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "add" || result.Package != "gamma@3.2.1" || result.Packages != 3 || len(invocations) != 2 {
		t.Fatalf("unexpected resolver result: %#v invocations=%#v", result, invocations)
	}
	version := strings.Join(invocations[0], "\n")
	resolution := strings.Join(invocations[1], "\n")
	for _, required := range []string{
		"--read-only", "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pull=always",
	} {
		if !strings.Contains(version, required) {
			t.Fatalf("version check lacks %s: %s", required, version)
		}
	}
	for _, required := range []string{
		"--read-only", "--network=bridge", "--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--package-lock-only=true", "--ignore-scripts=true", "--save-exact=true", "--allow-directory=none",
		"--allow-file=none", "--allow-git=none", "--allow-remote=none", "--min-release-age=3",
		"--registry=https://registry.npmjs.org/", "gamma@3.2.1",
	} {
		if !strings.Contains(resolution, required) {
			t.Fatalf("resolution lacks %s: %s", required, resolution)
		}
	}
	for _, prohibited := range []string{"must-not-cross", "NPM_TOKEN", "docker.sock", "--privileged", loaded.SourceRoot} {
		if strings.Contains(version+resolution, prohibited) {
			t.Fatalf("resolver exposed %s", prohibited)
		}
	}
	entries, err := os.ReadDir(output)
	if err != nil {
		t.Fatal(err)
	}
	if names := []string{entries[0].Name(), entries[1].Name()}; !slices.Equal(names, []string{"package-lock.json", "package.json"}) {
		t.Fatalf("unexpected candidate files: %#v", names)
	}
	if _, err := os.Stat(filepath.Join(output, "owned")); !os.IsNotExist(err) {
		t.Fatalf("lifecycle script output escaped: %v", err)
	}
	candidateManifest, err := os.ReadFile(result.Manifest)
	if err != nil || !strings.Contains(string(candidateManifest), `"gamma":"3.2.1"`) || !strings.Contains(string(candidateManifest), `"preinstall"`) {
		t.Fatalf("unexpected candidate manifest: %s err=%v", candidateManifest, err)
	}
}

func TestResolveRejectsDenyFeedBeforeDocker(t *testing.T) {
	loaded := resolverProject(t)
	called := false
	engine := Engine{execute: func(context.Context, io.Reader, io.Writer, io.Writer, ...string) error {
		called = true
		return nil
	}}
	feed := staticFetcher{"https://example.test/deny.csv": []byte("Ecosystem,Namespace,Name,Version,Artifact\nnpm,,gamma,3.2.1,gamma.tgz\n")}
	_, err := Resolve(context.Background(), engine, loaded, ResolveRequest{Package: "gamma@3.2.1", OutputDirectory: filepath.Join(t.TempDir(), "candidate")}, feed, time.Now(), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "gamma@3.2.1") {
		t.Fatalf("deny feed did not reject requested package: %v", err)
	}
	if called {
		t.Fatal("Docker started before requested package passed deny feeds")
	}
}

func TestResolveRejectsUnexpectedContainerOutput(t *testing.T) {
	loaded := resolverProject(t)
	engine := Engine{execute: func(_ context.Context, _ io.Reader, stdout, _ io.Writer, args ...string) error {
		joined := strings.Join(args, "\n")
		if strings.HasSuffix(joined, "npm\n--version") {
			_, _ = io.WriteString(stdout, "12.0.2\n")
			return nil
		}
		stage := resolverStageFromArgs(t, args)
		addDependencyToResolverFixture(t, stage, "gamma", "3.2.1")
		if err := os.WriteFile(filepath.Join(stage, "owned"), []byte("unexpected"), 0o600); err != nil {
			t.Fatal(err)
		}
		return nil
	}}
	output := filepath.Join(t.TempDir(), "candidate")
	_, err := Resolve(context.Background(), engine, loaded, ResolveRequest{Package: "gamma@3.2.1", OutputDirectory: output}, staticFetcher{"https://example.test/deny.csv": cleanFeed()}, time.Now(), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "unexpected output") {
		t.Fatalf("unexpected container output was accepted: %v", err)
	}
	if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
		t.Fatalf("rejected output was committed: %v", statErr)
	}
}

func TestResolveRejectsUnrequestedManifestMutation(t *testing.T) {
	loaded := resolverProject(t)
	engine := Engine{execute: func(_ context.Context, _ io.Reader, stdout, _ io.Writer, args ...string) error {
		joined := strings.Join(args, "\n")
		if strings.HasSuffix(joined, "npm\n--version") {
			_, _ = io.WriteString(stdout, "12.0.2\n")
			return nil
		}
		stage := resolverStageFromArgs(t, args)
		addDependencyToResolverFixture(t, stage, "gamma", "3.2.1")
		manifestFilename := filepath.Join(stage, "package.json")
		contents, err := os.ReadFile(manifestFilename)
		if err != nil {
			t.Fatal(err)
		}
		var manifest map[string]any
		if err := json.Unmarshal(contents, &manifest); err != nil {
			t.Fatal(err)
		}
		manifest["scripts"] = map[string]any{"postinstall": "touch /workspace/owned"}
		contents, _ = json.Marshal(manifest)
		if err := os.WriteFile(manifestFilename, contents, 0o600); err != nil {
			t.Fatal(err)
		}
		return nil
	}}
	output := filepath.Join(t.TempDir(), "candidate")
	_, err := Resolve(context.Background(), engine, loaded, ResolveRequest{Package: "gamma@3.2.1", OutputDirectory: output}, staticFetcher{"https://example.test/deny.csv": cleanFeed()}, time.Now(), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "beyond the requested dependency") {
		t.Fatalf("unrequested package.json mutation was accepted: %v", err)
	}
}

func TestResolverRequiresPinnedNPM12ImageAndExactPackageVersion(t *testing.T) {
	loaded := testProject(t, true)
	loaded.Spec.Resolver = &ResolverSpec{Image: "node:latest", NPMVersion: "11.19.0"}
	if err := loaded.Validate(false); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("mutable resolver image accepted: %v", err)
	}
	loaded.Spec.Resolver.Image = "registry.example.test/library/node@sha256:" + strings.Repeat("e", 64)
	if err := loaded.Validate(false); err == nil || !strings.Contains(err.Error(), "npm 12") {
		t.Fatalf("npm 11 resolver accepted: %v", err)
	}
	for _, value := range []string{"gamma", "gamma@latest", "https://example.test/gamma.tgz", "file:../gamma"} {
		if _, err := parseResolveTarget(value, false); err == nil {
			t.Fatalf("non-exact package accepted: %s", value)
		}
	}
}

func resolverProject(t *testing.T) LoadedSpec {
	t.Helper()
	loaded := testProject(t, true)
	loaded.Spec.Resolver = &ResolverSpec{
		Image:      "registry.example.test/library/node@sha256:" + strings.Repeat("e", 64),
		NPMVersion: "12.0.2",
	}
	if err := loaded.Validate(false); err != nil {
		t.Fatal(err)
	}
	return loaded
}

func resolverStageFromArgs(t *testing.T, args []string) string {
	t.Helper()
	for _, arg := range args {
		const prefix = "--mount=type=bind,src="
		const suffix = ",dst=/workspace"
		if strings.HasPrefix(arg, prefix) && strings.HasSuffix(arg, suffix) {
			return strings.TrimSuffix(strings.TrimPrefix(arg, prefix), suffix)
		}
	}
	t.Fatalf("resolver invocation lacks workspace mount: %#v", args)
	return ""
}

func addDependencyToResolverFixture(t *testing.T, stage, name, version string) {
	t.Helper()
	manifestFilename := filepath.Join(stage, "package.json")
	contents, err := os.ReadFile(manifestFilename)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(contents, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["dependencies"] = map[string]any{name: version}
	contents, _ = json.Marshal(manifest)
	if err := os.WriteFile(manifestFilename, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	lockfile := `{
  "name": "fixture",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "fixture", "dependencies": {"gamma": "3.2.1"}},
    "node_modules/alpha": {"version": "1.2.3", "integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="},
    "node_modules/@scope/beta": {"name": "@scope/beta", "version": "2.0.0"},
    "node_modules/gamma": {"version": "3.2.1", "integrity": "sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=="}
  }
}`
	if err := os.WriteFile(filepath.Join(stage, "package-lock.json"), []byte(lockfile), 0o600); err != nil {
		t.Fatal(err)
	}
}
