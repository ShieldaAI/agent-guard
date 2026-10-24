# Changelog

## 0.1.0-alpha.1 — 2026-10-24

Release notes are prepared; npm publication is pending the release checks below.

- Check deadlines again when a handler result settles, so synchronous work cannot return success
  after its deadline while the cancellation timer is waiting to run.
- Enforce the canonical JSON byte limit during normalization instead of building an oversized
  serialization before rejecting it.
- Disable persisted CI checkout credentials, bound workflow runtimes, and add CodeQL, dependency review and Dependabot configuration.
- Clarify package selection and the local demo setup; no provider credentials are needed.
- Reject custom policy decisions when their supplied task snapshot changes during evaluation, before a handler runs or an approval is consumed.
- Strengthen scenario catalog 1.1.0 to detect premature dispatch and incorrect cost settlement; bound asynchronous conformance cases with configurable timeouts.
- Exercise the MCP bridge against the official SDK v2.4.0 and document the difference between local request cancellation and remote work stopping.
- Remove obsolete build output and rebuild packages before packing.
- Compile packed public types and README examples, execute a packaged MCP consumer, and require a clean committed checkout with aligned versions before publication.

These changes are not included in the published `0.1.0-alpha.0` packages. See the [release review](docs/quality-review.md) for test results and outstanding publication checks.

## 0.1.0-alpha.0 — 2026-10-24

Published all three packages under `@shieldaai` with the `alpha` dist-tag.

- Initial TypeScript execution core for explicitly registered tools and scoped task trees.
- Immutable prepared actions, exact approvals, tenant and recipient gates, shared sensitivity, literal secret scanning and atomic local budgets.
- MCP client bridge with explicit approval of tool metadata.
- Ten versioned protective scenarios with malicious and benign executable fixtures.
- Package-consumer verification, CI, threat model and release documentation.

This alpha is experimental and keeps state in one process. See the threat model for deployment requirements and limitations.
