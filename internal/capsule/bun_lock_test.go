package capsule

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseBunLockReadsRegistryPackagesAndAliases(t *testing.T) {
	root := t.TempDir()
	filename := filepath.Join(root, "bun.lock")
	contents := `{
  // Bun lockfiles are JSONC.
  "lockfileVersion": 1,
  "packages": {
    "alpha": ["alpha@1.2.3", "", {}, "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="],
    "alias": ["@scope/beta@2.3.4-beta.1", "", {}, "sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=="],
    "local": ["local@workspace:packages/local"],
  },
}`
	if err := os.WriteFile(filename, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	packages, err := ParseDependencyLock(filename)
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 2 || packages[0].Name != "@scope/beta" || packages[0].Version != "2.3.4-beta.1" || packages[1].Name != "alpha" {
		t.Fatalf("unexpected packages: %#v", packages)
	}
}

func TestParseBunLockRejectsOpaqueAndUnverifiedResolutions(t *testing.T) {
	for _, test := range []struct {
		name       string
		resolution string
		integrity  string
		want       string
	}{
		{name: "git", resolution: "alpha@github:owner/repo#main", integrity: `"sha512-AAAA"`, want: "non-registry"},
		{name: "tarball", resolution: "alpha@https://example.test/alpha.tgz", integrity: `"sha512-AAAA"`, want: "non-registry"},
		{name: "missing integrity", resolution: "alpha@1.2.3", integrity: `""`, want: "lacks sha512 integrity"},
	} {
		t.Run(test.name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "bun.lock")
			contents := `{"lockfileVersion":1,"packages":{"alpha":["` + test.resolution + `","",{},` + test.integrity + `,],},}`
			if err := os.WriteFile(filename, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ParseBunLock(filename); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ParseBunLock error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestParseDependencyLockRejectsBinaryBunLock(t *testing.T) {
	if _, err := ParseDependencyLock(filepath.Join(t.TempDir(), "bun.lockb")); err == nil || !strings.Contains(err.Error(), "reviewable text") {
		t.Fatalf("unexpected error: %v", err)
	}
}
