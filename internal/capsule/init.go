package capsule

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultBunVersion = "1.3.14"
	defaultBunImage   = "docker.io/oven/bun@sha256:e10577f0db68676a7024391c6e5cb4b879ebd17188ab750cf10024a6d700e5c4"
	defaultDenyFeed   = "https://socket.dev/api/public/supply-chain-attacks/keyv-and-cacheable-compromise/packages.csv"
)

type InitRequest struct {
	Root       string
	SourceURI  string
	BunVersion string
	Image      string
}

type InitResult struct {
	Schema      int    `json:"schema"`
	Manager     string `json:"manager"`
	Version     string `json:"version"`
	Spec        string `json:"spec"`
	Dockerfile  string `json:"dockerfile"`
	PackageJSON string `json:"packageJSON"`
	Bunfig      string `json:"bunfig"`
}

func InitializeBun(request InitRequest) (InitResult, error) {
	if request.Root == "" {
		return InitResult{}, errors.New("initialization root is required")
	}
	root, err := filepath.Abs(request.Root)
	if err != nil {
		return InitResult{}, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return InitResult{}, fmt.Errorf("resolve initialization root: %w", err)
	}
	if parsed, parseErr := url.Parse(request.SourceURI); parseErr != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return InitResult{}, errors.New("--source-uri must be an HTTPS repository URL without credentials")
	}
	if request.BunVersion == "" {
		request.BunVersion = defaultBunVersion
	}
	if !bunVersion.MatchString(request.BunVersion) {
		return InitResult{}, errors.New("--bun-version must be an exact Bun version")
	}
	if request.Image == "" {
		if request.BunVersion != defaultBunVersion {
			return InitResult{}, errors.New("a non-default Bun version requires --resolver-image with a matching immutable digest")
		}
		request.Image = defaultBunImage
	}
	if !digestReference.MatchString(request.Image) {
		return InitResult{}, errors.New("--resolver-image must be an immutable registry sha256 digest")
	}

	capsuleDirectory := filepath.Join(root, ".capsule")
	if _, err := os.Lstat(capsuleDirectory); err == nil {
		return InitResult{}, errors.New(".capsule already exists; refusing to overwrite reviewed policy")
	} else if !errors.Is(err, os.ErrNotExist) {
		return InitResult{}, err
	}
	packageFilename := filepath.Join(root, "package.json")
	packageContents, err := os.ReadFile(packageFilename)
	if err != nil {
		return InitResult{}, fmt.Errorf("read package.json: %w", err)
	}
	manifest, err := decodeJSONObject(packageContents)
	if err != nil {
		return InitResult{}, err
	}
	expectedManager := "bun@" + request.BunVersion
	if existing, present := manifest["packageManager"]; present && existing != expectedManager {
		return InitResult{}, fmt.Errorf("package.json packageManager must be exactly %q", expectedManager)
	}
	manifest["packageManager"] = expectedManager
	if trusted, present := manifest["trustedDependencies"]; present {
		if _, ok := trusted.([]any); !ok {
			return InitResult{}, errors.New("package.json trustedDependencies must be an array")
		}
	} else {
		manifest["trustedDependencies"] = []any{}
	}
	updatedManifest, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return InitResult{}, err
	}
	updatedManifest = append(updatedManifest, '\n')

	bunfigFilename := filepath.Join(root, "bunfig.toml")
	bunfigExists := false
	if info, err := os.Lstat(bunfigFilename); err == nil {
		if !info.Mode().IsRegular() {
			return InitResult{}, errors.New("bunfig.toml must be a regular file without symlinks")
		}
		bunfigExists = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return InitResult{}, err
	}

	if err := os.Mkdir(capsuleDirectory, 0o700); err != nil {
		return InitResult{}, err
	}
	cleanupCapsule := true
	defer func() {
		if cleanupCapsule {
			_ = os.RemoveAll(capsuleDirectory)
		}
	}()

	spec := Spec{
		Schema:                SchemaVersion,
		SourceURI:             request.SourceURI,
		Source:                "..",
		Workdir:               "/workspace",
		Network:               "none",
		WritablePaths:         []string{"/workspace/node_modules"},
		Command:               []string{"bun", "test"},
		MinimumReleaseAgeDays: 3,
		DenyFeeds:             []string{defaultDenyFeed},
		Intake: &IntakeSpec{
			Dockerfile: "Dockerfile",
			Inputs:     []string{"package.json", "bun.lock", "bunfig.toml"},
			Lockfile:   "bun.lock",
		},
		Resolver: &ResolverSpec{Image: request.Image, BunVersion: request.BunVersion},
	}
	specContents, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return InitResult{}, err
	}
	specContents = append(specContents, '\n')
	dockerfileContents := bunDockerfile(request.Image)
	if err := atomicWrite(filepath.Join(capsuleDirectory, "capsule.json"), specContents, 0o600); err != nil {
		return InitResult{}, err
	}
	if err := atomicWrite(filepath.Join(capsuleDirectory, "Dockerfile"), dockerfileContents, 0o600); err != nil {
		return InitResult{}, err
	}
	if !bunfigExists {
		bunfig := []byte("[install]\nregistry = \"https://registry.npmjs.org/\"\nminimumReleaseAge = 259200\n\n[install.lockfile]\nsave = true\n")
		if err := atomicWrite(bunfigFilename, bunfig, 0o600); err != nil {
			return InitResult{}, err
		}
	}
	if err := atomicWrite(packageFilename, updatedManifest, 0o600); err != nil {
		return InitResult{}, err
	}
	if err := appendCapsuleGitignore(root); err != nil {
		return InitResult{}, err
	}
	cleanupCapsule = false
	return InitResult{
		Schema:      SchemaVersion,
		Manager:     "bun",
		Version:     request.BunVersion,
		Spec:        filepath.Join(capsuleDirectory, "capsule.json"),
		Dockerfile:  filepath.Join(capsuleDirectory, "Dockerfile"),
		PackageJSON: packageFilename,
		Bunfig:      bunfigFilename,
	}, nil
}

func bunDockerfile(image string) []byte {
	return []byte("FROM " + image + `
ARG BUN_CONFIG_MINIMUM_RELEASE_AGE
ARG BUN_CONFIG_REGISTRY
WORKDIR /workspace
COPY package.json bun.lock bunfig.toml ./
RUN test "$BUN_CONFIG_MINIMUM_RELEASE_AGE" = "259200" \
    && test "$BUN_CONFIG_REGISTRY" = "https://registry.npmjs.org/" \
    && bun -e 'const path="package.json"; const manifest=await Bun.file(path).json(); delete manifest.scripts; await Bun.write(path, JSON.stringify(manifest, null, 2)+"\n")' \
    && bun install --frozen-lockfile --minimum-release-age="$BUN_CONFIG_MINIMUM_RELEASE_AGE" --registry="$BUN_CONFIG_REGISTRY" --no-progress --no-summary \
    && rm -rf /root/.bun /tmp/*
RUN mkdir -p /capsule-tmp && chown 65532:65532 /capsule-tmp
USER 65532:65532
ENV HOME=/home/capsule
`)
}

func appendCapsuleGitignore(root string) error {
	filename := filepath.Join(root, ".gitignore")
	contents, err := os.ReadFile(filename)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	text := string(contents)
	entries := []string{".capsule/state.json", ".capsule/intake.cdx.json"}
	for _, entry := range entries {
		found := false
		for _, line := range strings.Split(text, "\n") {
			if strings.TrimSpace(line) == entry {
				found = true
				break
			}
		}
		if !found {
			if text != "" && !strings.HasSuffix(text, "\n") {
				text += "\n"
			}
			text += entry + "\n"
		}
	}
	return atomicWrite(filename, []byte(text), 0o600)
}
