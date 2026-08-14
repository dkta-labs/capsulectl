package capsule

import (
	"os"
	"path/filepath"
	"runtime"
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

func TestPrepareRuntimeSourceAtUsesSelectedDaemonVisibleRoot(t *testing.T) {
	sourceRoot := t.TempDir()
	stageRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourceRoot, "app.js"), []byte("safe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stage, err := prepareRuntimeSourceAt(sourceRoot, stageRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stage)
	if filepath.Dir(stage) != stageRoot {
		t.Fatalf("runtime source staged outside selected daemon-visible root: %s", stage)
	}
	sourceInfo, err := os.Stat(sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	stageParentInfo, err := os.Stat(filepath.Dir(stage))
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(sourceInfo, stageParentInfo) {
		t.Fatalf("runtime source staged inside source root: %s", stage)
	}
	if _, err := os.Stat(filepath.Join(stage, "app.js")); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeSourceStageRootSelectionPreservesDaemonVisibility(t *testing.T) {
	root := t.TempDir()
	sourceRoot := filepath.Join(root, "project")
	daemonHome := filepath.Join(root, "home")
	for _, directory := range []string{sourceRoot, daemonHome} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, testCase := range []struct {
		name            string
		operatingSystem string
		expected        string
	}{
		{name: "linux", operatingSystem: "linux", expected: root},
		{name: "darwin", operatingSystem: "darwin", expected: daemonHome},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			stageRoot, err := runtimeSourceStageRootFor(sourceRoot, testCase.operatingSystem, daemonHome)
			if err != nil {
				t.Fatal(err)
			}
			if stageRoot != testCase.expected {
				t.Fatalf("selected staging root %s, want %s", stageRoot, testCase.expected)
			}
		})
	}
}

func TestPrepareRuntimeSourceAtRejectsSourceDescendantStageRoot(t *testing.T) {
	sourceRoot := t.TempDir()
	stageRoot := filepath.Join(sourceRoot, ".capsulectl-source")
	if _, err := prepareRuntimeSourceAt(sourceRoot, stageRoot); err == nil || !strings.Contains(err.Error(), "outside the source root") {
		t.Fatalf("runtime source stage inside source root was accepted: %v", err)
	}
	outer := t.TempDir()
	if err := os.Symlink(filepath.Join(sourceRoot, "nested"), filepath.Join(outer, "stage")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(sourceRoot, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareRuntimeSourceAt(sourceRoot, filepath.Join(outer, "stage")); err == nil || !strings.Contains(err.Error(), "outside the source root") {
		t.Fatalf("symlinked runtime stage inside source root was accepted: %v", err)
	}
}

func TestValidateRuntimeStageRootRejectsSameFileAlias(t *testing.T) {
	sourceRoot := t.TempDir()
	aliasParent := t.TempDir()
	alias := filepath.Join(aliasParent, "source-alias")
	if err := os.Symlink(sourceRoot, alias); err != nil {
		t.Fatal(err)
	}
	if err := validateRuntimeStageRoot(sourceRoot, filepath.Join(alias, "stage")); err == nil || !strings.Contains(err.Error(), "outside the source root") {
		t.Fatalf("same-file runtime stage alias was accepted: %v", err)
	}
}

func TestValidateRuntimeStageRootRejectsDarwinAlternateCaseAlias(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("alternate-case alias requires Darwin filesystem semantics")
	}
	root := t.TempDir()
	sourceRoot := filepath.Join(root, "SourceRoot")
	if err := os.Mkdir(sourceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	alternate := filepath.Join(root, "sOURCEROOT")
	if _, err := os.Stat(alternate); err != nil {
		t.Skip("filesystem is case-sensitive")
	}
	if err := validateRuntimeStageRoot(sourceRoot, filepath.Join(alternate, "stage")); err == nil || !strings.Contains(err.Error(), "outside the source root") {
		t.Fatalf("alternate-case runtime stage alias was accepted: %v", err)
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
