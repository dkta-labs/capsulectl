## Problem

## Decision

## Security invariants

- [ ] No host environment, credentials, home, SSH agent, Docker socket, or writable Git metadata is newly exposed.
- [ ] Deny-feed, resolver, provenance, and promotion paths still fail closed.
- [ ] New container permissions or network access are explicitly documented and tested, or none were added.

## Verification

- [ ] `go test ./...`
- [ ] `go vet ./...`
- [ ] Both commands build.
- [ ] Observable behavior was exercised from the real CLI.

## Tracking

Closes #
