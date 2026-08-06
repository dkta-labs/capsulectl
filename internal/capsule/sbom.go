package capsule

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type packageLock struct {
	LockfileVersion int                        `json:"lockfileVersion"`
	Packages        map[string]packageLockItem `json:"packages"`
}

type packageLockItem struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Integrity string `json:"integrity"`
}

type cyclonedxBOM struct {
	BOMFormat   string               `json:"bomFormat"`
	SpecVersion string               `json:"specVersion"`
	Version     int                  `json:"version"`
	Components  []cyclonedxComponent `json:"components"`
}

type cyclonedxComponent struct {
	Type    string          `json:"type"`
	Name    string          `json:"name"`
	Version string          `json:"version"`
	PURL    string          `json:"purl"`
	Hashes  []cyclonedxHash `json:"hashes,omitempty"`
}

type cyclonedxHash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}

func ParsePackageLock(filename string) ([]Package, error) {
	contents, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var lock packageLock
	decoder := json.NewDecoder(strings.NewReader(string(contents)))
	if err := decoder.Decode(&lock); err != nil {
		return nil, fmt.Errorf("decode npm lockfile: %w", err)
	}
	if lock.LockfileVersion < 2 || len(lock.Packages) == 0 {
		return nil, errors.New("npm package-lock.json version 2 or newer is required")
	}
	packages := make([]Package, 0, len(lock.Packages)-1)
	for path, item := range lock.Packages {
		if path == "" || item.Version == "" {
			continue
		}
		name := item.Name
		if name == "" {
			name = packageNameFromLockPath(path)
		}
		if name == "" {
			return nil, fmt.Errorf("cannot derive package name from lockfile path %s", path)
		}
		packages = append(packages, Package{Name: name, Version: item.Version, Integrity: item.Integrity})
	}
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}
		return packages[i].Name < packages[j].Name
	})
	return packages, nil
}

func ParseCycloneDX(filename string) ([]Package, error) {
	contents, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var bom cyclonedxBOM
	if err := json.Unmarshal(contents, &bom); err != nil {
		return nil, fmt.Errorf("decode CycloneDX SBOM: %w", err)
	}
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion == "" || len(bom.Components) == 0 {
		return nil, errors.New("invalid or empty CycloneDX SBOM")
	}
	packages := make([]Package, 0, len(bom.Components))
	for _, component := range bom.Components {
		if component.Type != "library" || component.Name == "" || component.Version == "" {
			continue
		}
		packages = append(packages, Package{Name: component.Name, Version: component.Version})
	}
	if len(packages) == 0 {
		return nil, errors.New("CycloneDX SBOM contains no library components")
	}
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}
		return packages[i].Name < packages[j].Name
	})
	return packages, nil
}

func packageNameFromLockPath(path string) string {
	marker := "node_modules/"
	index := strings.LastIndex(path, marker)
	if index < 0 {
		return ""
	}
	name := path[index+len(marker):]
	parts := strings.Split(name, "/")
	if strings.HasPrefix(name, "@") && len(parts) >= 2 {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

func WriteCycloneDX(filename string, packages []Package) error {
	bom := cyclonedxBOM{BOMFormat: "CycloneDX", SpecVersion: "1.5", Version: 1}
	for _, pkg := range packages {
		component := cyclonedxComponent{
			Type:    "library",
			Name:    pkg.Name,
			Version: pkg.Version,
			PURL:    npmPURL(pkg.Name, pkg.Version),
		}
		if hash, ok := integrityHash(pkg.Integrity); ok {
			component.Hashes = []cyclonedxHash{hash}
		}
		bom.Components = append(bom.Components, component)
	}
	contents, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return err
	}
	contents = append(contents, '\n')
	return atomicWrite(filename, contents, 0o600)
}

func npmPURL(name, version string) string {
	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(strings.TrimPrefix(name, "@"), "/", 2)
		if len(parts) == 2 {
			return "pkg:npm/%40" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]) + "@" + url.PathEscape(version)
		}
	}
	return "pkg:npm/" + url.PathEscape(name) + "@" + url.PathEscape(version)
}

func integrityHash(integrity string) (cyclonedxHash, bool) {
	if !strings.HasPrefix(integrity, "sha512-") {
		return cyclonedxHash{}, false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(integrity, "sha512-"))
	if err != nil || len(decoded) != sha512.Size {
		return cyclonedxHash{}, false
	}
	return cyclonedxHash{Algorithm: "SHA-512", Content: hex.EncodeToString(decoded)}, true
}

func atomicWrite(filename string, contents []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(filename), ".capsule-state-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, filename)
}
