package capsule

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
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
		"--mount=type=volume,dst=/capsule-deps", "--env=NODE_PATH=/capsule-deps",
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
	engine := Engine{execute: func(_ context.Context, _ io.Reader, stdout, _ io.Writer, args ...string) error {
		invocations = append(invocations, append([]string(nil), args...))
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
		if err := validateDockerfile(filename); err == nil || !strings.Contains(err.Error(), expected) {
			t.Fatalf("Dockerfile %q was not rejected for %s: %v", contents, expected, err)
		}
	}
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
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"fixture","private":true}`), 0o600); err != nil {
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
