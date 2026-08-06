package capsule

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	SchemaVersion       = 1
	intakePolicyVersion = 2
)

var (
	sha256Hex       = regexp.MustCompile(`^[a-f0-9]{64}$`)
	digestReference = regexp.MustCompile(`^(?:[a-z0-9][a-z0-9.-]*(?::[1-9][0-9]{0,4})?/[a-z0-9][a-z0-9._/-]*@)?sha256:[a-f0-9]{64}$`)
	portMapping     = regexp.MustCompile(`^127\.0\.0\.1:[1-9][0-9]{0,4}:[1-9][0-9]{0,4}$`)
	environmentName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	secretName      = regexp.MustCompile(`(?i)(AUTH|COOKIE|CREDENTIAL|DATABASE_URL|KEY|PASS|SECRET|SESSION|TOKEN)`)
	npmVersion      = regexp.MustCompile(`^(?:1[2-9]|[2-9][0-9])\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
)

type Spec struct {
	Schema                int               `json:"schema"`
	Image                 string            `json:"image,omitempty"`
	InputSHA256           string            `json:"inputSHA256,omitempty"`
	Provenance            string            `json:"provenance,omitempty"`
	SBOM                  string            `json:"sbom,omitempty"`
	SourceURI             string            `json:"sourceURI"`
	Source                string            `json:"source"`
	Workdir               string            `json:"workdir"`
	Network               string            `json:"network"`
	Ports                 []string          `json:"ports,omitempty"`
	WritablePaths         []string          `json:"writablePaths,omitempty"`
	Environment           map[string]string `json:"environment,omitempty"`
	Command               []string          `json:"command"`
	MinimumReleaseAgeDays int               `json:"minimumReleaseAgeDays"`
	DenyFeeds             []string          `json:"denyFeeds"`
	Intake                *IntakeSpec       `json:"intake,omitempty"`
	Resolver              *ResolverSpec     `json:"resolver,omitempty"`
}

type IntakeSpec struct {
	Dockerfile string   `json:"dockerfile"`
	Inputs     []string `json:"inputs"`
	Lockfile   string   `json:"lockfile"`
}

type ResolverSpec struct {
	Image      string `json:"image"`
	NPMVersion string `json:"npmVersion"`
}

type Package struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Integrity string `json:"integrity,omitempty"`
}

type FeedEvidence struct {
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Artifacts int    `json:"artifacts"`
	CheckedAt string `json:"checkedAt"`
}

type State struct {
	Schema      int            `json:"schema"`
	Image       string         `json:"image"`
	InputSHA256 string         `json:"inputSHA256"`
	BuiltAt     string         `json:"builtAt"`
	Packages    []Package      `json:"packages"`
	Feeds       []FeedEvidence `json:"feeds"`
}

type LoadedSpec struct {
	Filename   string
	Directory  string
	SourceRoot string
	Spec       Spec
}

func LoadSpec(filename string) (LoadedSpec, error) {
	absolute, err := filepath.Abs(filename)
	if err != nil {
		return LoadedSpec{}, err
	}
	contents, err := os.ReadFile(absolute)
	if err != nil {
		return LoadedSpec{}, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(contents)))
	decoder.DisallowUnknownFields()
	var spec Spec
	if err := decoder.Decode(&spec); err != nil {
		return LoadedSpec{}, fmt.Errorf("decode spec: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return LoadedSpec{}, errors.New("decode spec: trailing JSON value")
	}
	directory := filepath.Dir(absolute)
	if spec.Source == "" {
		return LoadedSpec{}, errors.New("source is required")
	}
	sourceRoot, err := filepath.Abs(filepath.Join(directory, spec.Source))
	if err != nil {
		return LoadedSpec{}, err
	}
	sourceRoot, err = filepath.EvalSymlinks(sourceRoot)
	if err != nil {
		return LoadedSpec{}, fmt.Errorf("resolve source: %w", err)
	}
	info, err := os.Stat(sourceRoot)
	if err != nil || !info.IsDir() {
		return LoadedSpec{}, fmt.Errorf("source is not a directory: %s", sourceRoot)
	}
	loaded := LoadedSpec{Filename: absolute, Directory: directory, SourceRoot: sourceRoot, Spec: spec}
	if err := loaded.Validate(false); err != nil {
		return LoadedSpec{}, err
	}
	return loaded, nil
}

func (loaded LoadedSpec) Validate(requireImage bool) error {
	spec := loaded.Spec
	if spec.Schema != SchemaVersion {
		return fmt.Errorf("schema must be %d", SchemaVersion)
	}
	parsedSource, err := url.Parse(spec.SourceURI)
	if err != nil || parsedSource.Scheme != "https" || parsedSource.Host == "" || parsedSource.User != nil {
		return errors.New("sourceURI must be an HTTPS repository URL without credentials")
	}
	if requireImage && !digestReference.MatchString(spec.Image) {
		return errors.New("image must be an immutable sha256 image ID or registry digest")
	}
	if spec.Image != "" && !digestReference.MatchString(spec.Image) {
		return errors.New("image must be an immutable sha256 image ID or registry digest")
	}
	if spec.Image != "" {
		if spec.SBOM == "" || spec.Provenance == "" || !sha256Hex.MatchString(spec.InputSHA256) {
			return errors.New("a committed image digest requires lowercase inputSHA256, CycloneDX SBOM, and SLSA provenance")
		}
		if err := validateRelativePath(spec.SBOM); err != nil {
			return fmt.Errorf("sbom %q: %w", spec.SBOM, err)
		}
		if err := validateRelativePath(spec.Provenance); err != nil {
			return fmt.Errorf("provenance %q: %w", spec.Provenance, err)
		}
	} else if spec.SBOM != "" || spec.Provenance != "" || spec.InputSHA256 != "" {
		return errors.New("committed inputSHA256, SBOM, and provenance require an image digest")
	}
	if spec.Workdir == "" || !filepath.IsAbs(spec.Workdir) || filepath.Clean(spec.Workdir) != spec.Workdir {
		return errors.New("workdir must be a clean absolute container path")
	}
	if spec.Network != "none" && spec.Network != "bridge" {
		return errors.New("network must be none or bridge")
	}
	if len(spec.Command) == 0 || spec.Command[0] == "" {
		return errors.New("command is required")
	}
	if spec.MinimumReleaseAgeDays < 3 || spec.MinimumReleaseAgeDays > 30 {
		return errors.New("minimumReleaseAgeDays must be between 3 and 30")
	}
	if len(spec.DenyFeeds) == 0 {
		return errors.New("at least one HTTPS deny feed is required")
	}
	for _, feed := range spec.DenyFeeds {
		if !strings.HasPrefix(feed, "https://") {
			return fmt.Errorf("deny feed must use HTTPS: %s", feed)
		}
	}
	if spec.Network == "none" && len(spec.Ports) > 0 {
		return errors.New("ports require bridge networking")
	}
	for _, port := range spec.Ports {
		if !portMapping.MatchString(port) {
			return fmt.Errorf("port must bind explicitly to localhost: %s", port)
		}
		parts := strings.Split(port, ":")
		if parts[1] == "0" || parts[2] == "0" {
			return fmt.Errorf("invalid port mapping: %s", port)
		}
	}
	seenWritable := map[string]bool{}
	for _, path := range spec.WritablePaths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || path == "/workspace" {
			return fmt.Errorf("writable path must be a clean absolute subpath: %s", path)
		}
		if path == "/workspace/.git" || strings.HasPrefix(path, "/workspace/.git/") {
			return errors.New("writable paths cannot expose repository metadata")
		}
		if seenWritable[path] {
			return fmt.Errorf("duplicate writable path: %s", path)
		}
		seenWritable[path] = true
	}
	for name, value := range spec.Environment {
		if !environmentName.MatchString(name) {
			return fmt.Errorf("invalid environment name: %s", name)
		}
		if secretName.MatchString(name) {
			return fmt.Errorf("credential-like environment variables are prohibited: %s", name)
		}
		if strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("environment value contains NUL: %s", name)
		}
	}
	if spec.Intake != nil {
		if spec.Intake.Dockerfile == "" || filepath.IsAbs(spec.Intake.Dockerfile) {
			return errors.New("intake dockerfile must be relative to the spec")
		}
		if len(spec.Intake.Inputs) == 0 {
			return errors.New("intake inputs are required")
		}
		if spec.Intake.Lockfile == "" {
			return errors.New("intake lockfile is required")
		}
		seen := map[string]bool{}
		for _, input := range spec.Intake.Inputs {
			if err := validateRelativePath(input); err != nil {
				return fmt.Errorf("intake input %q: %w", input, err)
			}
			if seen[input] {
				return fmt.Errorf("duplicate intake input: %s", input)
			}
			seen[input] = true
		}
		if !seen[spec.Intake.Lockfile] {
			return errors.New("intake lockfile must be one of the explicit inputs")
		}
	}
	if spec.Resolver != nil {
		if spec.Intake == nil {
			return errors.New("resolver requires intake configuration")
		}
		if !digestReference.MatchString(spec.Resolver.Image) {
			return errors.New("resolver image must be an immutable registry sha256 digest")
		}
		if !npmVersion.MatchString(spec.Resolver.NPMVersion) {
			return errors.New("resolver npmVersion must be an exact npm 12 or newer version")
		}
		lockDirectory := filepath.Dir(spec.Intake.Lockfile)
		manifest := filepath.Join(lockDirectory, "package.json")
		if lockDirectory == "." {
			manifest = "package.json"
		}
		manifestInput := false
		for _, input := range spec.Intake.Inputs {
			manifestInput = manifestInput || input == manifest
		}
		if filepath.Base(spec.Intake.Lockfile) != "package-lock.json" || !manifestInput {
			return errors.New("resolver requires package.json and package-lock.json in the same intake directory")
		}
	}
	return nil
}

func validateRelativePath(path string) error {
	if path == "" || filepath.IsAbs(path) || filepath.Clean(path) != path || path == "." || strings.HasPrefix(path, ".."+string(filepath.Separator)) {
		return errors.New("path must stay within the source root")
	}
	return nil
}

func (loaded LoadedSpec) StateFilename() string {
	return filepath.Join(loaded.Directory, "state.json")
}

func (loaded LoadedSpec) ReadState() (State, error) {
	contents, err := os.ReadFile(loaded.StateFilename())
	if err != nil {
		return State{}, fmt.Errorf("read capsule state: %w", err)
	}
	var state State
	decoder := json.NewDecoder(strings.NewReader(string(contents)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return State{}, fmt.Errorf("decode capsule state: %w", err)
	}
	if state.Schema != SchemaVersion || !digestReference.MatchString(state.Image) || state.InputSHA256 == "" {
		return State{}, errors.New("capsule state is invalid")
	}
	return state, nil
}

func (loaded LoadedSpec) ResolveImageAndState() (string, *State, error) {
	if loaded.Spec.Image != "" {
		if err := loaded.Validate(true); err != nil {
			return "", nil, err
		}
		digest, err := loaded.InputDigest()
		if err != nil {
			return "", nil, err
		}
		if digest != loaded.Spec.InputSHA256 {
			return "", nil, errors.New("dependency inputs changed after the committed capsule was promoted")
		}
		if err := VerifyCommittedProvenance(loaded); err != nil {
			return "", nil, err
		}
		return loaded.Spec.Image, nil, nil
	}
	state, err := loaded.ReadState()
	if err != nil {
		return "", nil, errors.New("no committed image digest and no valid local intake state; run capsulectl intake")
	}
	if loaded.Spec.Intake == nil {
		return "", nil, errors.New("local intake state requires an intake specification")
	}
	digest, err := loaded.InputDigest()
	if err != nil {
		return "", nil, err
	}
	if digest != state.InputSHA256 {
		return "", nil, errors.New("dependency inputs changed after intake; rebuild the capsule")
	}
	return state.Image, &state, nil
}

func (loaded LoadedSpec) PackagesForImage(state *State) ([]Package, error) {
	if state != nil {
		return append([]Package(nil), state.Packages...), nil
	}
	if loaded.Spec.SBOM == "" {
		return nil, errors.New("committed image has no CycloneDX SBOM")
	}
	filename, err := secureRegularFile(loaded.Directory, loaded.Spec.SBOM)
	if err != nil {
		return nil, fmt.Errorf("read committed SBOM: %w", err)
	}
	return ParseCycloneDX(filename)
}

func (loaded LoadedSpec) InputDigest() (string, error) {
	if loaded.Spec.Intake == nil {
		return "", errors.New("intake is not configured")
	}
	hash := sha256.New()
	hash.Write([]byte("$intake-policy-version"))
	hash.Write([]byte{0})
	hash.Write([]byte(strconv.Itoa(intakePolicyVersion)))
	hash.Write([]byte{0})
	hash.Write([]byte("$minimum-release-age-days"))
	hash.Write([]byte{0})
	hash.Write([]byte(strconv.Itoa(loaded.Spec.MinimumReleaseAgeDays)))
	hash.Write([]byte{0})
	if loaded.Spec.Resolver != nil {
		hash.Write([]byte("$resolver-image"))
		hash.Write([]byte{0})
		hash.Write([]byte(loaded.Spec.Resolver.Image))
		hash.Write([]byte{0})
		hash.Write([]byte("$resolver-npm-version"))
		hash.Write([]byte{0})
		hash.Write([]byte(loaded.Spec.Resolver.NPMVersion))
		hash.Write([]byte{0})
	}
	dockerfile, err := secureRegularFile(loaded.Directory, loaded.Spec.Intake.Dockerfile)
	if err != nil {
		return "", err
	}
	dockerfileContents, err := os.ReadFile(dockerfile)
	if err != nil {
		return "", err
	}
	hash.Write([]byte("$dockerfile"))
	hash.Write([]byte{0})
	hash.Write(dockerfileContents)
	hash.Write([]byte{0})
	inputs := append([]string(nil), loaded.Spec.Intake.Inputs...)
	sort.Strings(inputs)
	for _, relative := range inputs {
		filename, err := secureRegularFile(loaded.SourceRoot, relative)
		if err != nil {
			return "", err
		}
		contents, err := os.ReadFile(filename)
		if err != nil {
			return "", err
		}
		if len(contents) > 64<<20 {
			return "", fmt.Errorf("intake input exceeds 64 MiB: %s", relative)
		}
		hash.Write([]byte(relative))
		hash.Write([]byte{0})
		hash.Write(contents)
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func secureRegularFile(root, relative string) (string, error) {
	if err := validateRelativePath(relative); err != nil {
		return "", err
	}
	filename := filepath.Join(root, relative)
	info, err := os.Lstat(filename)
	if err != nil {
		return "", fmt.Errorf("read intake input %s: %w", relative, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("intake input must be a regular file without symlinks: %s", relative)
	}
	return filename, nil
}
