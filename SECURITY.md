# Security Policy

## Reporting

Do not open a public GitHub issue for suspected vulnerabilities.

Use GitHub private vulnerability reporting if it is enabled for this repository. If it is not enabled yet, contact the repository maintainers privately first and request a non-public reporting channel before sharing details.

Before the repository is made public, the maintainer should replace this section with a concrete security contact.

## Scope

Security-sensitive areas include:

- authentication and authorization
- bootstrap credentials
- secret storage and rotation
- admin web UI session handling
- `SigV4` verification
- configuration and environment variable handling
- storage path and filesystem safety

## Disclosure Expectations

- provide a clear reproduction path when possible
- include affected version, commit, or branch if known
- avoid public disclosure until a fix or mitigation is ready

## Supported Versions

The project is pre-release. Until the first stable release, only the latest `main` branch state should be considered in scope for security fixes.
