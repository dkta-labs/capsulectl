package capsule

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const (
	statementType           = "https://in-toto.io/Statement/v1"
	provenancePredicateType = "https://slsa.dev/provenance/v1"
	capsuleBuildType        = "https://github.com/dkta-labs/capsulectl/provenance/v1"
	capsuleBuilderID        = "https://github.com/dkta-labs/capsulectl"
	promotionFreshness      = time.Hour
)

var (
	gitRevision       = regexp.MustCompile(`^[a-f0-9]{40}$`)
	registryReference = regexp.MustCompile(`^[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
)

type ArtifactReference struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type PromotionBundle struct {
	Schema         int               `json:"schema"`
	Image          string            `json:"image"`
	SourceURI      string            `json:"sourceURI"`
	SourceRevision string            `json:"sourceRevision"`
	InputSHA256    string            `json:"inputSHA256"`
	CreatedAt      string            `json:"createdAt"`
	Archive        ArtifactReference `json:"archive"`
	SBOM           ArtifactReference `json:"sbom"`
	Provenance     ArtifactReference `json:"provenance"`
	Feeds          []FeedEvidence    `json:"feeds"`
}

type ProvenanceSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type ProvenanceParameters struct {
	SourceURI             string   `json:"sourceURI"`
	SourceRevision        string   `json:"sourceRevision"`
	InputSHA256           string   `json:"inputSHA256"`
	SBOMSHA256            string   `json:"sbomSHA256"`
	MinimumReleaseAgeDays int      `json:"minimumReleaseAgeDays"`
	DenyFeeds             []string `json:"denyFeeds"`
}

type ProvenanceDependency struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

type ProvenanceBuildDefinition struct {
	BuildType            string                 `json:"buildType"`
	ExternalParameters   ProvenanceParameters   `json:"externalParameters"`
	InternalParameters   map[string]any         `json:"internalParameters"`
	ResolvedDependencies []ProvenanceDependency `json:"resolvedDependencies"`
}

type ProvenanceBuilder struct {
	ID string `json:"id"`
}

type ProvenanceMetadata struct {
	InvocationID string `json:"invocationId"`
	StartedOn    string `json:"startedOn"`
	FinishedOn   string `json:"finishedOn"`
}

type ProvenanceRunDetails struct {
	Builder  ProvenanceBuilder  `json:"builder"`
	Metadata ProvenanceMetadata `json:"metadata"`
}

type ProvenancePredicate struct {
	BuildDefinition ProvenanceBuildDefinition `json:"buildDefinition"`
	RunDetails      ProvenanceRunDetails      `json:"runDetails"`
}

type ProvenanceStatement struct {
	Type          string              `json:"_type"`
	Subject       []ProvenanceSubject `json:"subject"`
	PredicateType string              `json:"predicateType"`
	Predicate     ProvenancePredicate `json:"predicate"`
}

type BundleResult struct {
	Schema      int            `json:"schema"`
	Directory   string         `json:"directory"`
	Bundle      string         `json:"bundle"`
	Archive     string         `json:"archive"`
	SBOM        string         `json:"sbom"`
	Provenance  string         `json:"provenance"`
	Image       string         `json:"image"`
	InputSHA256 string         `json:"inputSHA256"`
	Feeds       []FeedEvidence `json:"feeds"`
}

type PromoteResult struct {
	Schema         int    `json:"schema"`
	Image          string `json:"image"`
	SourceURI      string `json:"sourceURI"`
	SourceRevision string `json:"sourceRevision"`
	InputSHA256    string `json:"inputSHA256"`
	SBOMSHA256     string `json:"sbomSHA256"`
	Provenance     string `json:"provenance"`
}

type PromoterEngine struct {
	Binary       string
	Host         string
	Home         string
	DockerConfig string
	execute      func(context.Context, io.Reader, io.Writer, io.Writer, ...string) error
}

func PreparePromotion(ctx context.Context, engine Engine, loaded LoadedSpec, fetcher FeedFetcher, sourceRevision, outputDirectory string, now time.Time, stdout, stderr io.Writer) (BundleResult, error) {
	if !gitRevision.MatchString(sourceRevision) {
		return BundleResult{}, errors.New("source revision must be a full lowercase 40-character Git commit SHA")
	}
	if loaded.Spec.Image != "" {
		return BundleResult{}, errors.New("promotion bundles require fresh local intake state, not a committed image")
	}
	check, err := Check(ctx, loaded, fetcher, now)
	if err != nil {
		return BundleResult{}, err
	}
	state, err := loaded.ReadState()
	if err != nil {
		return BundleResult{}, err
	}
	if state.Image != check.Image || state.InputSHA256 == "" {
		return BundleResult{}, errors.New("capsule intake state does not match the checked image")
	}
	sbomSource, err := secureRegularFile(loaded.Directory, "intake.cdx.json")
	if err != nil {
		return BundleResult{}, fmt.Errorf("read intake SBOM: %w", err)
	}
	if _, err := ParseCycloneDX(sbomSource); err != nil {
		return BundleResult{}, fmt.Errorf("validate intake SBOM: %w", err)
	}
	sbomDigest, sbomBytes, err := fileSHA256(sbomSource)
	if err != nil {
		return BundleResult{}, err
	}
	bases, err := dockerfileBaseImages(filepath.Join(loaded.Directory, loaded.Spec.Intake.Dockerfile))
	if err != nil {
		return BundleResult{}, err
	}
	absoluteOutput, err := filepath.Abs(outputDirectory)
	if err != nil {
		return BundleResult{}, err
	}
	if _, err := os.Lstat(absoluteOutput); err == nil {
		return BundleResult{}, fmt.Errorf("promotion output already exists: %s", absoluteOutput)
	} else if !errors.Is(err, os.ErrNotExist) {
		return BundleResult{}, err
	}
	parent := filepath.Dir(absoluteOutput)
	stage, err := os.MkdirTemp(parent, ".capsule-promotion-")
	if err != nil {
		return BundleResult{}, err
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0o700); err != nil {
		return BundleResult{}, err
	}
	sbomTarget := filepath.Join(stage, "capsule.cdx.json")
	if err := copyRegularFile(sbomSource, sbomTarget); err != nil {
		return BundleResult{}, err
	}
	started := now.UTC()
	statement := buildProvenance(loaded, state, sourceRevision, sbomDigest, bases, started, started)
	provenanceTarget := filepath.Join(stage, "capsule.provenance.json")
	if err := writeJSON(provenanceTarget, statement); err != nil {
		return BundleResult{}, err
	}
	provenanceDigest, provenanceBytes, err := fileSHA256(provenanceTarget)
	if err != nil {
		return BundleResult{}, err
	}
	archiveTarget := filepath.Join(stage, "capsule-image.tar")
	if err := engine.command(ctx, nil, stdout, stderr, "save", "--output="+archiveTarget, state.Image); err != nil {
		return BundleResult{}, fmt.Errorf("export capsule image: %w", err)
	}
	archiveDigest, archiveBytes, err := fileSHA256(archiveTarget)
	if err != nil {
		return BundleResult{}, err
	}
	bundle := PromotionBundle{
		Schema:         SchemaVersion,
		Image:          state.Image,
		SourceURI:      loaded.Spec.SourceURI,
		SourceRevision: sourceRevision,
		InputSHA256:    state.InputSHA256,
		CreatedAt:      now.UTC().Format(time.RFC3339),
		Archive:        ArtifactReference{Path: filepath.Base(archiveTarget), SHA256: archiveDigest, Bytes: archiveBytes},
		SBOM:           ArtifactReference{Path: filepath.Base(sbomTarget), SHA256: sbomDigest, Bytes: sbomBytes},
		Provenance:     ArtifactReference{Path: filepath.Base(provenanceTarget), SHA256: provenanceDigest, Bytes: provenanceBytes},
		Feeds:          check.Feeds,
	}
	bundleTarget := filepath.Join(stage, "promotion-bundle.json")
	if err := writeJSON(bundleTarget, bundle); err != nil {
		return BundleResult{}, err
	}
	if err := os.Rename(stage, absoluteOutput); err != nil {
		return BundleResult{}, err
	}
	return BundleResult{
		Schema:      SchemaVersion,
		Directory:   absoluteOutput,
		Bundle:      filepath.Join(absoluteOutput, filepath.Base(bundleTarget)),
		Archive:     filepath.Join(absoluteOutput, filepath.Base(archiveTarget)),
		SBOM:        filepath.Join(absoluteOutput, filepath.Base(sbomTarget)),
		Provenance:  filepath.Join(absoluteOutput, filepath.Base(provenanceTarget)),
		Image:       state.Image,
		InputSHA256: state.InputSHA256,
		Feeds:       check.Feeds,
	}, nil
}

func DiscoverPromoterEngine(ctx context.Context) (PromoterEngine, error) {
	binary, err := exec.LookPath("docker")
	if err != nil {
		return PromoterEngine{}, errors.New("docker CLI is required")
	}
	host := os.Getenv("DOCKER_HOST")
	if host == "" {
		command := exec.CommandContext(ctx, binary, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
		output, err := command.Output()
		if err != nil {
			return PromoterEngine{}, fmt.Errorf("resolve Docker context: %w", err)
		}
		host = strings.TrimSpace(string(output))
	}
	if !strings.HasPrefix(host, "unix://") {
		return PromoterEngine{}, errors.New("capsule promoter must use a local Unix socket")
	}
	if runtime.GOOS == "darwin" && !strings.Contains(strings.TrimPrefix(host, "unix://"), string(filepath.Separator)+".colima"+string(filepath.Separator)) {
		return PromoterEngine{}, errors.New("macOS capsule promotion requires a Colima VM Docker context")
	}
	if runtime.GOOS == "linux" && os.Getenv("GITHUB_ACTIONS") != "true" && os.Getenv("CAPSULE_PROMOTER_EPHEMERAL") != "1" {
		return PromoterEngine{}, errors.New("Linux capsule promotion requires an ephemeral CI runner")
	}
	return PromoterEngine{
		Binary:       binary,
		Host:         host,
		Home:         os.Getenv("HOME"),
		DockerConfig: os.Getenv("DOCKER_CONFIG"),
	}, nil
}

func Promote(ctx context.Context, engine PromoterEngine, bundleFilename, destination, expectedSourceRevision, provenanceOutput string, now time.Time, stdout, stderr io.Writer) (PromoteResult, error) {
	if !registryReference.MatchString(destination) || strings.HasSuffix(destination, ":latest") {
		return PromoteResult{}, errors.New("destination must be an explicit non-latest registry/repository:tag reference")
	}
	if !gitRevision.MatchString(expectedSourceRevision) {
		return PromoteResult{}, errors.New("expected source revision must be a full lowercase 40-character Git commit SHA")
	}
	if provenanceOutput == "" {
		return PromoteResult{}, errors.New("promotion provenance output is required")
	}
	absoluteProvenance, err := filepath.Abs(provenanceOutput)
	if err != nil {
		return PromoteResult{}, err
	}
	if _, err := os.Lstat(absoluteProvenance); err == nil {
		return PromoteResult{}, errors.New("promotion provenance output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return PromoteResult{}, err
	}
	parentInfo, err := os.Stat(filepath.Dir(absoluteProvenance))
	if err != nil || !parentInfo.IsDir() {
		return PromoteResult{}, errors.New("promotion provenance parent directory does not exist")
	}
	bundle, directory, err := readPromotionBundle(bundleFilename)
	if err != nil {
		return PromoteResult{}, err
	}
	if bundle.SourceRevision != expectedSourceRevision {
		return PromoteResult{}, errors.New("promotion bundle source revision does not match the reviewed revision")
	}
	if err := validateFreshEvidence(bundle, now); err != nil {
		return PromoteResult{}, err
	}
	archive, err := verifyArtifact(directory, bundle.Archive)
	if err != nil {
		return PromoteResult{}, fmt.Errorf("verify image archive: %w", err)
	}
	sbom, err := verifyArtifact(directory, bundle.SBOM)
	if err != nil {
		return PromoteResult{}, fmt.Errorf("verify SBOM: %w", err)
	}
	if _, err := ParseCycloneDX(sbom); err != nil {
		return PromoteResult{}, fmt.Errorf("validate SBOM: %w", err)
	}
	provenance, err := verifyArtifact(directory, bundle.Provenance)
	if err != nil {
		return PromoteResult{}, fmt.Errorf("verify provenance: %w", err)
	}
	statement, err := ReadProvenance(provenance)
	if err != nil {
		return PromoteResult{}, err
	}
	if err := verifyProvenance(statement, bundle.Image, bundle.SourceURI, bundle.SourceRevision, bundle.InputSHA256, bundle.SBOM.SHA256); err != nil {
		return PromoteResult{}, err
	}
	if err := engine.command(ctx, nil, stdout, stderr, "load", "--input="+archive); err != nil {
		return PromoteResult{}, fmt.Errorf("load capsule archive: %w", err)
	}
	var inspect bytes.Buffer
	if err := engine.command(ctx, nil, &inspect, stderr, "image", "inspect", "--format={{.Id}}", bundle.Image); err != nil {
		return PromoteResult{}, fmt.Errorf("inspect loaded capsule: %w", err)
	}
	if strings.TrimSpace(inspect.String()) != bundle.Image {
		return PromoteResult{}, errors.New("loaded capsule image ID does not match the promotion bundle")
	}
	if err := engine.command(ctx, nil, stdout, stderr, "tag", bundle.Image, destination); err != nil {
		return PromoteResult{}, fmt.Errorf("tag capsule image: %w", err)
	}
	if err := engine.command(ctx, nil, stdout, stderr, "push", destination); err != nil {
		return PromoteResult{}, fmt.Errorf("push capsule image: %w", err)
	}
	inspect.Reset()
	if err := engine.command(ctx, nil, &inspect, stderr, "image", "inspect", "--format={{json .RepoDigests}}", destination); err != nil {
		return PromoteResult{}, fmt.Errorf("inspect promoted capsule: %w", err)
	}
	immutable, digest, err := promotedDigest(destination, inspect.Bytes())
	if err != nil {
		return PromoteResult{}, err
	}
	repository := destination[:strings.LastIndex(destination, ":")]
	statement.Subject = []ProvenanceSubject{{Name: repository, Digest: map[string]string{"sha256": digest}}}
	statement.Predicate.RunDetails.Metadata.FinishedOn = now.UTC().Format(time.RFC3339)
	if err := writeJSON(absoluteProvenance, statement); err != nil {
		return PromoteResult{}, err
	}
	return PromoteResult{
		Schema:         SchemaVersion,
		Image:          immutable,
		SourceURI:      bundle.SourceURI,
		SourceRevision: bundle.SourceRevision,
		InputSHA256:    bundle.InputSHA256,
		SBOMSHA256:     bundle.SBOM.SHA256,
		Provenance:     absoluteProvenance,
	}, nil
}

func (engine PromoterEngine) environment() []string {
	environment := []string{"PATH=" + os.Getenv("PATH"), "DOCKER_HOST=" + engine.Host}
	if engine.Home != "" {
		environment = append(environment, "HOME="+engine.Home)
	}
	if engine.DockerConfig != "" {
		environment = append(environment, "DOCKER_CONFIG="+engine.DockerConfig)
	}
	if temporary := os.Getenv("TMPDIR"); temporary != "" {
		environment = append(environment, "TMPDIR="+temporary)
	}
	return environment
}

func (engine PromoterEngine) command(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) error {
	if engine.execute != nil {
		return engine.execute(ctx, stdin, stdout, stderr, args...)
	}
	command := exec.CommandContext(ctx, engine.Binary, args...)
	command.Env = engine.environment()
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return CommandError{Code: exitError.ExitCode(), Err: err}
		}
		return err
	}
	return nil
}

func ReadProvenance(filename string) (ProvenanceStatement, error) {
	contents, err := os.ReadFile(filename)
	if err != nil {
		return ProvenanceStatement{}, fmt.Errorf("read provenance: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var statement ProvenanceStatement
	if err := decoder.Decode(&statement); err != nil {
		return ProvenanceStatement{}, fmt.Errorf("decode provenance: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ProvenanceStatement{}, errors.New("decode provenance: trailing JSON value")
	}
	return statement, nil
}

func VerifyCommittedProvenance(loaded LoadedSpec) error {
	if loaded.Spec.Image == "" {
		return nil
	}
	filename, err := secureRegularFile(loaded.Directory, loaded.Spec.Provenance)
	if err != nil {
		return fmt.Errorf("read committed provenance: %w", err)
	}
	sbom, err := secureRegularFile(loaded.Directory, loaded.Spec.SBOM)
	if err != nil {
		return fmt.Errorf("read committed SBOM: %w", err)
	}
	sbomDigest, _, err := fileSHA256(sbom)
	if err != nil {
		return err
	}
	statement, err := ReadProvenance(filename)
	if err != nil {
		return err
	}
	parameters := statement.Predicate.BuildDefinition.ExternalParameters
	return verifyProvenance(statement, loaded.Spec.Image, loaded.Spec.SourceURI, parameters.SourceRevision, loaded.Spec.InputSHA256, sbomDigest)
}

func readPromotionBundle(filename string) (PromotionBundle, string, error) {
	absolute, err := filepath.Abs(filename)
	if err != nil {
		return PromotionBundle{}, "", err
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() {
		return PromotionBundle{}, "", errors.New("promotion bundle must be a regular file without symlinks")
	}
	contents, err := os.ReadFile(absolute)
	if err != nil {
		return PromotionBundle{}, "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var bundle PromotionBundle
	if err := decoder.Decode(&bundle); err != nil {
		return PromotionBundle{}, "", fmt.Errorf("decode promotion bundle: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return PromotionBundle{}, "", errors.New("decode promotion bundle: trailing JSON value")
	}
	if bundle.Schema != SchemaVersion || !digestReference.MatchString(bundle.Image) || !gitRevision.MatchString(bundle.SourceRevision) || !sha256Hex.MatchString(bundle.InputSHA256) {
		return PromotionBundle{}, "", errors.New("promotion bundle is invalid")
	}
	return bundle, filepath.Dir(absolute), nil
}

func verifyArtifact(directory string, reference ArtifactReference) (string, error) {
	if reference.Path == "" || filepath.Base(reference.Path) != reference.Path || len(reference.SHA256) != 64 || reference.Bytes < 0 {
		return "", errors.New("artifact reference is invalid")
	}
	filename, err := secureRegularFile(directory, reference.Path)
	if err != nil {
		return "", err
	}
	digest, size, err := fileSHA256(filename)
	if err != nil {
		return "", err
	}
	if digest != reference.SHA256 || size != reference.Bytes {
		return "", errors.New("artifact digest or size does not match the promotion bundle")
	}
	return filename, nil
}

func validateFreshEvidence(bundle PromotionBundle, now time.Time) error {
	created, err := time.Parse(time.RFC3339, bundle.CreatedAt)
	if err != nil || created.After(now.Add(time.Minute)) || now.Sub(created) > promotionFreshness {
		return errors.New("promotion bundle is stale or has an invalid creation time")
	}
	if len(bundle.Feeds) == 0 {
		return errors.New("promotion bundle has no threat-feed evidence")
	}
	for _, feed := range bundle.Feeds {
		checked, err := time.Parse(time.RFC3339, feed.CheckedAt)
		if err != nil || checked.After(now.Add(time.Minute)) || now.Sub(checked) > promotionFreshness {
			return fmt.Errorf("threat-feed evidence is stale or invalid: %s", feed.URL)
		}
	}
	return nil
}

func promotedDigest(destination string, contents []byte) (string, string, error) {
	var digests []string
	if err := json.Unmarshal(bytes.TrimSpace(contents), &digests); err != nil {
		return "", "", fmt.Errorf("decode promoted image digests: %w", err)
	}
	repository := destination[:strings.LastIndex(destination, ":")]
	prefix := repository + "@sha256:"
	for _, value := range digests {
		if strings.HasPrefix(value, prefix) && len(value) == len(prefix)+64 {
			return value, strings.TrimPrefix(value, prefix), nil
		}
	}
	return "", "", errors.New("registry did not return an immutable digest for the promoted image")
}

func buildProvenance(loaded LoadedSpec, state State, sourceRevision, sbomDigest string, bases []string, started, finished time.Time) ProvenanceStatement {
	dependencies := make([]ProvenanceDependency, 0, len(bases))
	for _, base := range bases {
		parts := strings.Split(base, "@sha256:")
		dependencies = append(dependencies, ProvenanceDependency{URI: "pkg:docker/" + parts[0], Digest: map[string]string{"sha256": parts[1]}})
	}
	invocation := sha256.Sum256([]byte(state.Image + "\x00" + state.InputSHA256 + "\x00" + sourceRevision + "\x00" + started.Format(time.RFC3339Nano)))
	return ProvenanceStatement{
		Type:          statementType,
		Subject:       []ProvenanceSubject{{Name: "capsule-image", Digest: map[string]string{"sha256": strings.TrimPrefix(state.Image, "sha256:")}}},
		PredicateType: provenancePredicateType,
		Predicate: ProvenancePredicate{
			BuildDefinition: ProvenanceBuildDefinition{
				BuildType: capsuleBuildType,
				ExternalParameters: ProvenanceParameters{
					SourceURI:             loaded.Spec.SourceURI,
					SourceRevision:        sourceRevision,
					InputSHA256:           state.InputSHA256,
					SBOMSHA256:            sbomDigest,
					MinimumReleaseAgeDays: loaded.Spec.MinimumReleaseAgeDays,
					DenyFeeds:             append([]string(nil), loaded.Spec.DenyFeeds...),
				},
				InternalParameters:   map[string]any{},
				ResolvedDependencies: dependencies,
			},
			RunDetails: ProvenanceRunDetails{
				Builder: ProvenanceBuilder{ID: capsuleBuilderID},
				Metadata: ProvenanceMetadata{
					InvocationID: "urn:sha256:" + hex.EncodeToString(invocation[:]),
					StartedOn:    started.UTC().Format(time.RFC3339),
					FinishedOn:   finished.UTC().Format(time.RFC3339),
				},
			},
		},
	}
}

func verifyProvenance(statement ProvenanceStatement, image, sourceURI, sourceRevision, inputDigest, sbomDigest string) error {
	if statement.Type != statementType || statement.PredicateType != provenancePredicateType || len(statement.Subject) != 1 {
		return errors.New("provenance statement type or subject is invalid")
	}
	expectedImage := strings.TrimPrefix(image[strings.LastIndex(image, "@")+1:], "sha256:")
	if value := statement.Subject[0].Digest["sha256"]; value != expectedImage {
		return errors.New("provenance subject does not match the capsule image")
	}
	definition := statement.Predicate.BuildDefinition
	parameters := definition.ExternalParameters
	if definition.BuildType != capsuleBuildType || statement.Predicate.RunDetails.Builder.ID != capsuleBuilderID {
		return errors.New("provenance builder identity is invalid")
	}
	if parameters.SourceURI != sourceURI || parameters.SourceRevision != sourceRevision || parameters.InputSHA256 != inputDigest || parameters.SBOMSHA256 != sbomDigest {
		return errors.New("provenance parameters do not match the promotion inputs")
	}
	if !gitRevision.MatchString(parameters.SourceRevision) || len(parameters.InputSHA256) != 64 || len(parameters.SBOMSHA256) != 64 {
		return errors.New("provenance parameters are invalid")
	}
	return nil
}

func dockerfileBaseImages(filename string) ([]string, error) {
	contents, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var bases []string
	for _, raw := range strings.Split(string(contents), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "FROM") {
			continue
		}
		index := 1
		for index < len(fields) && strings.HasPrefix(fields[index], "--") {
			index++
		}
		if index >= len(fields) || !strings.Contains(fields[index], "@sha256:") {
			return nil, fmt.Errorf("invalid digest-pinned Dockerfile base image: %s", line)
		}
		bases = append(bases, fields[index])
	}
	if len(bases) == 0 {
		return nil, errors.New("intake Dockerfile has no FROM instruction")
	}
	return bases, nil
}

func fileSHA256(filename string) (string, int64, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func copyRegularFile(source, target string) error {
	contents, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return atomicWrite(target, contents, 0o600)
}

func writeJSON(filename string, value any) error {
	contents, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	contents = append(contents, '\n')
	return atomicWrite(filename, contents, 0o600)
}
