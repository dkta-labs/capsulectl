package capsule

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareRuntimeSourceExcludesHostDependenciesAndGitMetadata(t *testing.T) {
	root := t.TempDir()
	for name, contents := range map[string]string{
		"app.js":                      "console.log('safe')\n",
		".git/config":                 "credential = must-not-cross\n",
		"node_modules/owned/index.js": "throw new Error('host dependency crossed')\n",
	} {
		filename := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stage, err := prepareRuntimeSource(root)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stage)
	if _, err := os.Stat(filepath.Join(stage, "app.js")); err != nil {
		t.Fatal(err)
	}
	for _, excluded := range []string{".git", "node_modules"} {
		if _, err := os.Stat(filepath.Join(stage, excluded)); !os.IsNotExist(err) {
			t.Fatalf("excluded runtime path crossed boundary: %s err=%v", excluded, err)
		}
	}
}

func TestPrepareRuntimeSourceRejectsSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "target"), []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	_, err := prepareRuntimeSource(root)
	if err == nil || !strings.Contains(err.Error(), "symlinks require explicit review") {
		t.Fatalf("runtime symlink was accepted: %v", err)
	}
}
