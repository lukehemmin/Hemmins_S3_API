# Hemmins S3 API

Lightweight single-node object storage with `S3` compatibility, a built-in web UI, and Docker-first deployment.

## Status

This project is currently in the design stage.

The initial goal is to build a practical `S3`-compatible storage server that can run on a single node, stay lightweight, and still provide a usable admin experience through a web UI.

## Goals

- `S3`-compatible core API for common SDK and CLI workflows
- Single-node deployment with simple operations
- Local filesystem-based object storage
- Built-in web UI for administration
- Easy local and container-based execution

## Planned MVP

- Bucket create/delete/list/head
- Object upload/download/delete/head
- `ListObjectsV2`
- Multipart upload
- Presigned `GET` and `PUT`
- `AWS Signature Version 4` authentication
- Admin web UI
- Docker and `docker compose` support

## Non-Goals For MVP

- Multi-node clustering
- Replication and failover
- Full IAM compatibility
- Object versioning and lifecycle policies
- KMS-backed encryption

## Development Docs

Detailed engineering documents live under [`docs/development/`](./docs/development/).

- [Development Docs Index](./docs/development/README.md)
- [Product Spec](./docs/development/product-spec.md)
- [System Architecture](./docs/development/system-architecture.md)
- [Implementation Roadmap](./docs/development/implementation-roadmap.md)
- [Configuration Model](./docs/development/configuration-model.md)
- [S3 Compatibility Contract](./docs/development/s3-compatibility-matrix.md)
- [Security Model](./docs/development/security-model.md)
- [Operations Runbook](./docs/development/operations-runbook.md)

## Repository Metadata

- [Contributing Guide](./CONTRIBUTING.md)
- [Code Of Conduct](./CODE_OF_CONDUCT.md)
- [Security Policy](./SECURITY.md)
- License: `TBD` before public release

## Draft Runtime Files

- [Example Config](./config/config.example.yaml)
- [Example Env File](./.env.example)
- [Example Docker Compose](./deployments/docker/docker-compose.example.yml)

These files are draft runtime artifacts aligned with the current design documents. They define the intended configuration and deployment shape, but they are not fully runnable until the server implementation and Docker image are added.

## Direction

The current working direction is:

- `Go` for the main server
- `SQLite` for metadata
- Local filesystem for object blobs
- Single binary deployment where possible

This direction may still evolve during implementation, but the primary constraint remains the same: keep the system simple, predictable, and operational on a single node.
