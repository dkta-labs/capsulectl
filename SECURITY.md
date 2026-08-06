# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use GitHub's **Report a vulnerability** flow in the Security tab of this repository. Include:

- affected command and version or commit;
- the violated security invariant;
- the platform and container engine configuration;
- minimal reproduction steps;
- whether package code, host data, credentials, registry state, or provenance may have been exposed.

Do not include real credentials, tokens, private source, or customer data. Use synthetic canaries.

We will acknowledge the report through GitHub's private advisory workflow, assess severity and affected versions, and coordinate remediation and disclosure there.

## Supported versions

Until 1.0, only the latest tagged release receives security fixes. Pin release binaries by checksum and upgrade after reviewing release notes.

## Security boundaries

The intended invariants are documented in the README. Reports are especially valuable when they demonstrate any of these outcomes:

- package-controlled code observes inherited host environment or credentials;
- a host path outside declared source becomes readable or writable;
- repository `.git` data reaches runtime code;
- runtime code reaches the Docker socket;
- undeclared network access succeeds;
- mutable images or unreviewed inputs are accepted;
- a deny-feed failure or exact match fails open;
- stale, tampered, or mismatched SBOM/provenance is accepted;
- the promoter executes source or package-manager code.

## Operational incidents

If you suspect a capsule already exposed credentials, stop using those credentials and follow your own incident-response and rotation process. Do not send credential material to this project.
