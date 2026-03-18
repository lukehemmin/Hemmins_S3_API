# Contributing

## Scope

This repository is in the design and early implementation stage. Contributions are welcome, but changes should stay aligned with the single-node, S3-compatible, low-complexity direction documented under [`docs/development/`](./docs/development/).

## Before You Start

- Read [README.md](./README.md)
- Read [docs/development/README.md](./docs/development/README.md)
- Check whether the proposed change fits the documented MVP
- Open an issue first for large design changes, storage layout changes, or protocol changes

## Contribution Rules

- Keep changes scoped and reviewable
- Prefer updating docs and implementation together when behavior changes
- Do not silently expand the MVP scope
- Preserve backward compatibility unless the change is explicitly documented as breaking
- Add or update tests when behavior changes

## Pull Request Expectations

Each pull request should include:

- what changed
- why it changed
- any compatibility or migration impact
- any follow-up work that is intentionally left out

If the change affects `S3` behavior, also mention which parts of [`docs/development/s3-compatibility-matrix.md`](./docs/development/s3-compatibility-matrix.md) were updated or intentionally left unchanged.

## Design-Sensitive Areas

Open an issue or design discussion before changing any of the following:

- storage layout
- metadata schema
- durability guarantees
- config schema
- security bootstrap flow
- `S3` protocol behavior

## Development Status

Until `v1.0.0`, the project may change quickly. Contributors should expect documentation and interfaces to tighten over time.
