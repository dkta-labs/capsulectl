package capsule

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPreparePromotionBindsImageInputsSBOMAndReviewedSource(t *testing.T) {
	loaded, result, now := promotionFixture(t)
	bundle, _, err := readPromotionBundle(result.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Image != result.Image || bundle.InputSHA256 != result.InputSHA256 || bundle.SourceURI != loaded.Spec.SourceURI || bundle.SourceRevision != strings.Repeat("e", 40) {
		t.Fatalf("unexpected bundle: %#v", bundle)
	}
	if _, err := verifyArtifact(result.Directory, bundle.Archive); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyArtifact(result.Directory, bundle.SBOM); err != nil {
		t.Fatal(err)
	}
	provenance, err := ReadProvenance(result.Provenance)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyProvenance(provenance, bundle.Image, bundle.SourceURI, bundle.SourceRevision, bundle.InputSHA256, bundle.SBOM.SHA256); err != nil {
		t.Fatal(err)
	}
	if provenance.Predicate.RunDetails.Metadata.StartedOn != now.Format(time.RFC3339) || len(provenance.Predicate.BuildDefinition.ResolvedDependencies) != 1 {
		t.Fatalf("unexpected provenance: %#v", provenance)
	}
}

func TestPromoteVerifiesBundleBeforeFixedLoadTagAndPush(t *testing.T) {
	_, bundleResult, now := promotionFixture(t)
	localImage := bundleResult.Image
	destination := "localhost:5000/example/capsule:reviewed"
	registryDigest := strings.Repeat("f", 64)
	var invocations [][]string
	engine := PromoterEngine{execute: func(_ context.Context, _ io.Reader, stdout, _ io.Writer, args ...string) error {
		invocations = append(invocations, append([]string(nil), args...))
		if len(args) >= 2 && args[0] == "image" && args[1] == "inspect" {
			if strings.Contains(args[len(args)-1], "localhost:5000") {
				_, _ = io.WriteString(stdout, `["localhost:5000/example/capsule@sha256:`+registryDigest+`"]`)
			} else {
				_, _ = io.WriteString(stdout, localImage+"\n")
			}
		}
		return nil
	}}
	provenanceOutput := filepath.Join(t.TempDir(), "promoted.provenance.json")
	result, err := Promote(context.Background(), engine, bundleResult.Bundle, destination, strings.Repeat("e", 40), provenanceOutput, now.Add(5*time.Minute), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if result.Image != "localhost:5000/example/capsule@sha256:"+registryDigest || result.Provenance != provenanceOutput {
		t.Fatalf("unexpected promotion result: %#v", result)
	}
	if got := invocationCommands(invocations); got != "load,image,tag,push,image" {
		t.Fatalf("unexpected promoter commands: %s (%#v)", got, invocations)
	}
	statement, err := ReadProvenance(provenanceOutput)
	if err != nil {
		t.Fatal(err)
	}
	if statement.Subject[0].Name != "localhost:5000/example/capsule" || statement.Subject[0].Digest["sha256"] != registryDigest {
		t.Fatalf("promoted provenance lacks registry subject: %#v", statement.Subject)
	}
}

func TestPromoteRejectsTamperedArchiveBeforeDocker(t *testing.T) {
	_, result, now := promotionFixture(t)
	if err := os.WriteFile(result.Archive, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	invoked := false
	engine := PromoterEngine{execute: func(context.Context, io.Reader, io.Writer, io.Writer, ...string) error {
		invoked = true
		return nil
	}}
	_, err := Promote(context.Background(), engine, result.Bundle, "registry.example.test/example/capsule:reviewed", strings.Repeat("e", 40), filepath.Join(t.TempDir(), "promoted.json"), now.Add(time.Minute), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "digest or size") {
		t.Fatalf("tampered archive accepted: %v", err)
	}
	if invoked {
		t.Fatal("Docker was invoked before bundle verification completed")
	}
}

func TestCommittedCapsuleRejectsLockfileDrift(t *testing.T) {
	loaded, bundleResult, now := promotionFixture(t)
	registryDigest := strings.Repeat("f", 64)
	destination := "registry.example.test/example/capsule:reviewed"
	engine := PromoterEngine{execute: func(_ context.Context, _ io.Reader, stdout, _ io.Writer, args ...string) error {
		if len(args) >= 2 && args[0] == "image" && args[1] == "inspect" {
			if strings.Contains(args[len(args)-1], "registry.example.test") {
				_, _ = io.WriteString(stdout, `["registry.example.test/example/capsule@sha256:`+registryDigest+`"]`)
			} else {
				_, _ = io.WriteString(stdout, bundleResult.Image+"\n")
			}
		}
		return nil
	}}
	promotedProvenance := filepath.Join(t.TempDir(), "promoted.json")
	promoted, err := Promote(context.Background(), engine, bundleResult.Bundle, destination, strings.Repeat("e", 40), promotedProvenance, now.Add(time.Minute), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := copyRegularFile(bundleResult.SBOM, filepath.Join(loaded.Directory, "committed.cdx.json")); err != nil {
		t.Fatal(err)
	}
	if err := copyRegularFile(promotedProvenance, filepath.Join(loaded.Directory, "committed.provenance.json")); err != nil {
		t.Fatal(err)
	}
	loaded.Spec.Image = promoted.Image
	loaded.Spec.InputSHA256 = bundleResult.InputSHA256
	loaded.Spec.SBOM = "committed.cdx.json"
	loaded.Spec.Provenance = "committed.provenance.json"
	if _, _, err := loaded.ResolveImageAndState(); err != nil {
		t.Fatalf("valid committed capsule rejected: %v", err)
	}
	lockfile := filepath.Join(loaded.SourceRoot, loaded.Spec.Intake.Lockfile)
	if err := os.WriteFile(lockfile, []byte(`{"lockfileVersion":3,"packages":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loaded.ResolveImageAndState(); err == nil || !strings.Contains(err.Error(), "dependency inputs changed") {
		t.Fatalf("committed capsule accepted lockfile drift: %v", err)
	}
}

func TestInputDigestIncludesReleaseCooldownPolicy(t *testing.T) {
	loaded := testProject(t, true)
	before := mustInputDigest(t, loaded)
	loaded.Spec.MinimumReleaseAgeDays++
	after := mustInputDigest(t, loaded)
	if before == after {
		t.Fatal("release cooldown change did not invalidate dependency intake")
	}
}

func promotionFixture(t *testing.T) (LoadedSpec, BundleResult, time.Time) {
	t.Helper()
	loaded := testProject(t, true)
	dockerfile := "FROM node@sha256:" + strings.Repeat("a", 64) + "\nARG NPM_CONFIG_MIN_RELEASE_AGE\nARG NPM_CONFIG_ALLOW_GIT\nARG NPM_CONFIG_ALLOW_REMOTE\nARG NPM_CONFIG_SAVE_EXACT\n"
	if err := os.WriteFile(filepath.Join(loaded.Directory, loaded.Spec.Intake.Dockerfile), []byte(dockerfile), 0o600); err != nil {
		t.Fatal(err)
	}
	image := "sha256:" + strings.Repeat("c", 64)
	engine := Engine{execute: func(_ context.Context, _ io.Reader, stdout, _ io.Writer, args ...string) error {
		if len(args) >= 2 && args[0] == "image" && args[1] == "inspect" {
			_, _ = io.WriteString(stdout, image+"\n")
		}
		if len(args) >= 2 && args[0] == "save" && strings.HasPrefix(args[1], "--output=") {
			return os.WriteFile(strings.TrimPrefix(args[1], "--output="), []byte("docker archive"), 0o600)
		}
		return nil
	}}
	now := time.Date(2026, 8, 4, 18, 0, 0, 0, time.UTC)
	feed := staticFetcher{"https://example.test/deny.csv": cleanFeed()}
	if _, err := Intake(context.Background(), engine, loaded, feed, now, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "promotion")
	result, err := PreparePromotion(context.Background(), engine, loaded, feed, strings.Repeat("e", 40), output, now, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	return loaded, result, now
}

func invocationCommands(invocations [][]string) string {
	commands := make([]string, 0, len(invocations))
	for _, invocation := range invocations {
		if len(invocation) == 0 {
			continue
		}
		if invocation[0] == "image" {
			commands = append(commands, "image")
		} else {
			commands = append(commands, invocation[0])
		}
	}
	return strings.Join(commands, ",")
}
