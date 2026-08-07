package capsule

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitializeBunCreatesReviewableCapsule(t *testing.T) {
	root := t.TempDir()
	packageFilename := filepath.Join(root, "package.json")
	if err := os.WriteFile(packageFilename, []byte("{\n  \"name\": \"fixture\",\n  \"private\": true\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InitializeBun(InitRequest{Root: root, SourceURI: "https://github.com/dkta-labs/fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Manager != "bun" || result.Version != defaultBunVersion {
		t.Fatalf("unexpected result: %#v", result)
	}
	manifestContents, err := os.ReadFile(packageFilename)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestContents, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest["packageManager"] != "bun@"+defaultBunVersion {
		t.Fatalf("package manager not pinned: %#v", manifest)
	}
	trusted, ok := manifest["trustedDependencies"].([]any)
	if !ok || len(trusted) != 0 {
		t.Fatalf("trusted dependencies are not explicitly empty: %#v", manifest)
	}
	for _, filename := range []string{".capsule/capsule.json", ".capsule/Dockerfile", "bunfig.toml", ".gitignore"} {
		if info, err := os.Stat(filepath.Join(root, filename)); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("missing scaffold file %s: %v", filename, err)
		}
	}
	specContents, err := os.ReadFile(filepath.Join(root, ".capsule", "capsule.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(specContents), `"bunVersion": "1.3.14"`) || !strings.Contains(string(specContents), `"lockfile": "bun.lock"`) {
		t.Fatalf("unexpected spec: %s", specContents)
	}
	if _, err := LoadSpec(filepath.Join(root, ".capsule", "capsule.json")); err != nil {
		t.Fatalf("generated spec does not load before first resolution: %v", err)
	}
}

func TestInitializeBunRefusesPolicyOverwrite(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"fixture"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ".capsule"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := InitializeBun(InitRequest{Root: root, SourceURI: "https://github.com/dkta-labs/fixture"}); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("unexpected error: %v", err)
	}
}
