# Contributing

Thank you for helping improve `capsulectl`.

## Before opening a change

- Search existing issues and pull requests.
- Use a GitHub issue for behavior changes, new lockfile formats, new container-engine behavior, or changes to an isolation boundary.
- Report suspected vulnerabilities through GitHub private vulnerability reporting instead of a public issue; see [SECURITY.md](SECURITY.md).

## Development

Requirements: Go 1.24 or newer. Docker is needed only for end-to-end capsule exercises.

```sh
go test ./...
go vet ./...
go build ./cmd/capsulectl ./cmd/capsule-promoter
```

The project intentionally uses only the Go standard library. New dependencies require a concrete maintenance and security justification.

## Pull requests

Keep changes narrow and include tests for observable behavior. A security-boundary change must document:

1. the threat being addressed;
2. the invariant before and after the change;
3. the exact container or promotion invocation affected;
4. a fail-closed test that would catch a regression;
5. operator-visible verification evidence.

Do not weaken an invariant to make a fixture, platform, or package manager work. Fix the boundary or explicitly propose a scoped new contract.

Use `gofmt` on Go files. Commits should be reviewable and must not contain credentials, private repository data, generated local state, capsule image archives, or dependency caches.

## Certificate of Origin

By contributing, you certify that you have the right to submit the work under this repository's MIT license. Sign off commits with:

```text
Signed-off-by: Your Name <your-address@example.com>
```

using `git commit -s`.
