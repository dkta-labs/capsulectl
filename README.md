# capsulectl

[![CI](https://github.com/dkta-labs/capsulectl/actions/workflows/ci.yml/badge.svg)](https://github.com/dkta-labs/capsulectl/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`capsulectl` runs JavaScript dependency intake and dependency-controlled commands without exposing a credentialed workstation to package code.

It builds an immutable dependency image in a disposable Docker boundary, checks exact package versions against live deny feeds, binds the image to reviewed inputs, and executes repository code with no inherited host environment, home directory, keychain, SSH agent, Docker socket, cloud credentials, or writable Git metadata.

The repository also ships `capsule-promoter`, a deliberately separate command that promotes a verified, short-lived bundle without checking out or executing source code.

## Status

`capsulectl` is pre-1.0 security software. Its current intake and resolver implementation supports npm `package-lock.json` versions 2 and 3. Review the [security model](#security-model), pin release binaries by checksum, and validate the boundary for each repository before relying on it.

## Requirements

- Go 1.24 or newer to build from source.
- Docker Engine.
- macOS: Docker must use a [Colima](https://github.com/abiosoft/colima) VM context.
- Linux: run on an ephemeral GitHub Actions runner, or set `CAPSULECTL_EPHEMERAL_CI=1` only when the machine is independently guaranteed to be disposable.
- Dependency resolution: a registry image pinned by SHA-256 and containing the exact configured npm 12+ version.

## Install

Build both commands from a reviewed tag:

```sh
go install github.com/dkta-labs/capsulectl/cmd/capsulectl@latest
go install github.com/dkta-labs/capsulectl/cmd/capsule-promoter@latest
```

Commands installed from a module version report that version. An unversioned local checkout reports `dev`; release archives keep the version injected by the release workflow.

For production use, prefer release archives and verify them against the published `SHA256SUMS` file.

## Quick start

Create `.capsule/capsule.json` and `.capsule/Dockerfile`. Complete examples live in [`docs/examples`](docs/examples).

```json
{
  "schema": 1,
  "sourceURI": "https://github.com/example-org/example",
  "source": "..",
  "workdir": "/workspace",
  "network": "none",
  "writablePaths": [
    "/capsule-tmp",
    "/workspace/node_modules"
  ],
  "environment": {
    "TMPDIR": "/capsule-tmp"
  },
  "command": ["node", "--test"],
  "minimumReleaseAgeDays": 3,
  "denyFeeds": [
    "https://socket.dev/api/public/supply-chain-attacks/keyv-and-cacheable-compromise/packages.csv"
  ],
  "intake": {
    "dockerfile": "Dockerfile",
    "inputs": ["package.json", "package-lock.json"],
    "lockfile": "package-lock.json"
  },
  "resolver": {
    "image": "registry.example.com/example/node-npm12@sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "npmVersion": "12.0.2"
  }
}
```

Replace the resolver image with a reviewed image that exists in your registry and contains exactly the configured npm version. Keep local state out of version control:

```gitignore
.capsule/state.json
.capsule/intake.cdx.json
```

Then intake, inspect, and run:

```sh
capsulectl intake --spec .capsule/capsule.json
capsulectl check --spec .capsule/capsule.json
capsulectl plan --spec .capsule/capsule.json
capsulectl run --spec .capsule/capsule.json
```

`plan` prints the complete Docker invocation so the isolation boundary can be reviewed before execution.

## Commands

### `resolve`

Produce candidate dependency files in a new directory without modifying the repository:

```sh
capsulectl resolve \
  --spec .capsule/capsule.json \
  --package package-name@1.2.3 \
  --output resolution
```

Use `--dev` for a development dependency or `--remove` with a package name for removal. Resolution uses a digest-pinned image, exact npm 12+, no inherited environment or credentials, disabled lifecycle scripts, disabled git/remote dependencies, a release cooldown, and live deny-feed checks before and after npm runs.

Review the returned `package.json` and `package-lock.json`; `capsulectl` never applies them automatically.

### `intake`

Build an immutable dependency image from explicitly declared regular files:

```sh
capsulectl intake --spec .capsule/capsule.json
```

Intake rejects mutable base images, symlinked inputs, BuildKit secret/SSH mounts, unsupported lockfiles, and exact deny-feed matches. It records local image identity, input digest, package inventory, feed evidence, and a CycloneDX SBOM.

### `check`

Fail closed when reviewed inputs, image identity, package inventory, policy, provenance, SBOM, or live feed evidence no longer match:

```sh
capsulectl check --spec .capsule/capsule.json
```

### `run`

Run the configured command or an explicit override inside the verified capsule:

```sh
capsulectl run --spec .capsule/capsule.json
capsulectl run --spec .capsule/capsule.json -- node --test test/smoke.test.js
```

Source is copied from a read-only mount into a disposable tmpfs. `.git` and host `node_modules` are removed before execution. Writable paths are anonymous volumes. Network defaults to `none`; bridge networking requires explicit configuration and ports bind only to `127.0.0.1`.

### `bundle` and `capsule-promoter`

Create a one-hour promotion package after tests pass:

```sh
capsulectl bundle \
  --spec .capsule/capsule.json \
  --source-revision "$REVIEWED_FULL_SHA" \
  --output promotion-output
```

Promote it on a separate, approval-gated ephemeral worker:

```sh
capsule-promoter \
  --bundle promotion-output/promotion-bundle.json \
  --destination ghcr.io/example-org/example:reviewed-tag \
  --source-revision "$REVIEWED_FULL_SHA" \
  --provenance-out promoted.provenance.json
```

The promoter loads, verifies, tags, and pushes the bundled image. It does not clone source, build a Dockerfile, run a package manager, or execute repository code.

For GitHub Actions, [`.github/workflows/promote-capsule.yml`](.github/workflows/promote-capsule.yml) is a reusable, source-free promotion job. Call it by an immutable commit SHA and supply the reviewed promoter binary checksum, promotion bundle artifact, destination tag, and source revision.

## Security model

`capsulectl` is designed to contain package-controlled code, not declare it trustworthy.

Enforced boundaries include:

- no inherited host environment;
- disposable `HOME` and Docker configuration;
- no host home, SSH agent, keychain, Docker socket, cloud credentials, or repository `.git` mount;
- read-only source ingress and disposable writable storage;
- non-root runtime user, read-only root filesystem, dropped capabilities, PID/memory/CPU limits, and `no-new-privileges`;
- no runtime network unless explicitly enabled;
- immutable image and base-image references;
- exact package/version checks against all configured HTTPS deny feeds;
- feed failure is a hard failure;
- input, SBOM, provenance, and reviewed source bindings checked before reuse or promotion.

### Non-goals

- Detecting every malicious package. Deny feeds are one signal, not perfect malware detection.
- Safely running arbitrary container engines or privileged Docker builds.
- Protecting a non-ephemeral Linux host after the operator bypasses the ephemeral-runner guard.
- Securing publication credentials placed in dependency jobs. Keep publication and deployment separate.
- Supporting lockfile formats other than npm lockfile versions 2 and 3 today.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Repository adoption checklist

Before treating a new repository as ready, prove that:

- a host-only canary file and credential-like environment value are absent;
- repository and `.git` writes fail;
- root-filesystem persistence fails;
- outbound network fails with `network: "none"`;
- only declared writable paths succeed;
- a changed lockfile prevents image reuse;
- an exact deny-feed match prevents Docker build from starting.

## Development

```sh
go test ./...
go vet ./...
go build ./cmd/capsulectl ./cmd/capsule-promoter
```

The implementation uses only the Go standard library. See [CONTRIBUTING.md](CONTRIBUTING.md) before proposing a behavior or security-boundary change.

## License

MIT. See [LICENSE](LICENSE).
