# Joined MCP isolation acceptance

This milestone exercises a real untrusted MCP peer inside a disposable Linux container, connected to the managed MCP client and durable executor. A second profile routes the same kind of isolated peer through a trusted loopback HTTP credential gateway. The harness uses original synthetic data, temporary private host state and an already installed, explicitly pinned Node image. It never pulls an image, reads production credentials or contacts an external provider.

```sh
# Supply an operator-reviewed Node Linux image digest already installed locally.
export AGENT_GUARD_MCP_ISOLATION_IMAGE='node@sha256:YOUR_REVIEWED_DIGEST'
npm run verify:mcp-isolation -- --output artifacts/mcp-isolation-evidence.json
```

Create the output directory first. A Node image is required because the fixture is a standalone JavaScript JSON-RPC server; the Alpine image used by the existing shell sandbox tests is insufficient. The tested local image was `node@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53` (Linux arm64, Node 24.22.1). That architecture-specific cached image is local evidence, not an instruction to reuse it on other host architectures.

The command exits `0` only if all 21 named checks and cleanup pass, `1` for failed/unavailable evidence, and `2` for invalid CLI options or report-write failure. Without `--output`, it prints JSON after npm's build output. After building, call `node scripts/verify-mcp-isolation.mjs` for JSON-only stdout. `AGENT_GUARD_EXPECTED_HOST`, when supplied, must be exactly `Linux`, `macOS` or `Windows` and match the running host. Missing images, Docker support or mismatched hosts cannot produce a passing report.

## Boundaries exercised together

The [harness](../../scripts/verify-mcp-isolation.mjs) reuses `runDockerSandbox` to validate the local Linux daemon/image and `buildDockerCreateArgs` for the fixed launch restrictions. The peer has network disabled, a read-only root filesystem, uid 1000, no capabilities, no-new-privileges, default seccomp and bounded memory/CPU/processes. Only its original fixture and a nonsecret probe path are mounted read-only; its workspace is a private tmpfs. There is no Docker socket, host credential mount or inherited host environment in the guest.

The host checks Docker configuration as well as actual guest behavior. The fixture tests that the host's real synthetic secret file and credential environment are inaccessible, the root filesystem is not writable, only loopback exists, and an attempted socket connection to a reserved documentation address fails. The reserved-address probe is bounded and sends no data to an external service. Guest observations supplement host inspection; a production hostile peer's self-report alone would not establish isolation.

The local stdio profile passes real JSON-RPC messages through `ManagedMcpConnection` and `DurableExecutor`. It verifies:

- A permitted read reaches the peer, and one specifically approved write creates an actual guest file.
- A foreign-tenant request and a write without approval do not dispatch to the peer.
- A metadata-change notification quarantines the connection. Stale preparations cannot run; refresh requires renewed metadata approval.
- Reconnection disposes the original container and starts a new one. A new session cannot inherit old preparations or metadata approval.
- Revocation before dispatch sends no call. Revocation during an uncooperative request produces `UNKNOWN`, retains the reservation and forbids replay until host reconciliation.
- Oversized unframed output closes the bounded transport and quarantines work. The stdio bridge caps request/message buffering and total output, and waits for the Docker client process to close.

The fixture contains hostile tool-result text asking for credentials. It remains data; it cannot reconfigure the host's tool bindings, task grants or destination. The harness sends scripted requests rather than sampling a model, so this is enforcement evidence, not a prompt-injection detection rate.

## HTTP credentials and unknown outcomes

The remote profile uses real loopback HTTP through `createRestrictedFetch` and `createRestrictedMcpHttpTransport`. An approved host gateway authenticates one opaque fixture bearer token and forwards only JSON-RPC bodies to the isolated stdio peer. The bearer token remains at that approved gateway and is absent from guest environment/results and traces. A wrong token is rejected without a peer call.

A host-verified Ed25519 fixture proof binds the actual bearer token fingerprint, issuer, audience, subject, scopes and expiry. Seven changed-proof cases—wrong issuer, audience, subject, scope, expiry, signature or credential fingerprint—must fail before an HTTP request. Restoring the proof does not restore the old registration approval: explicit refresh and review are required. A redirect never forwards the token/body to a separate local collector, and an unapproved private-address fetch reaches no collector.

Some host authorization checks occur inside the tool handler after durable admission. A failed check can therefore produce an `UNKNOWN` reservation even when the fixture gateway received zero requests. The harness does not relabel that outcome as a pre-admission denial. It reconciles only after trusted fixture evidence establishes no dispatch, or after disposing the guest so pending work cannot resume. Metadata, flooded-output, cancellation and redirected-call failures are also reconciled using their respective termination/no-forward evidence. No failed action is automatically retried.

This is a synthetic authorization-proof and credential-gateway exercise. It does not implement or certify a real OAuth provider, TLS termination, discovery, JWKS rotation, refresh-token handling or company claim mapping. Those deployment checks remain open. The underlying authorization helper still requires claims already cryptographically verified by the trusted host.

## Evidence and release gates

Reports contain fixed check names, pass/fail values, image and fixture/evaluator hashes, host/runtime versions, effect counts and sanitized failure codes. They omit credentials, raw transcripts, task IDs and private file contents. A cleanup failure prevents a passing report; an owned container name may be included so the operator can remove it. Host staging is removed even if container removal fails.

The [regression tests](../../scripts/mcp-isolation.test.mjs) reject incomplete, duplicate and failing check sets, missing positive effects, invalid claims counts, leaked redirect requests, invalid image/host configuration and cleanup failure. The real test is opt-in during ordinary `npm run check`; the dedicated platform verifier requires it without skips alongside the five existing real sandbox tests. The platform workflow requires separate reviewed shell and Node image digests and retains both reports.

```sh
npm run build
AGENT_GUARD_MCP_ISOLATION_IMAGE='node@sha256:YOUR_REVIEWED_DIGEST' \
  node --test scripts/mcp-isolation.test.mjs

# Full platform acceptance also needs the shell image and the exact host name.
AGENT_GUARD_SANDBOX_IMAGE='alpine@sha256:YOUR_REVIEWED_DIGEST' \
AGENT_GUARD_MCP_ISOLATION_IMAGE='node@sha256:YOUR_REVIEWED_DIGEST' \
AGENT_GUARD_EXPECTED_HOST='macOS' node scripts/verify-platform.mjs
```

Local macOS plus a Linux Docker VM does not certify native Linux or Windows hosting. Windows ACL provisioning, each dedicated host's Docker controls, VM restart/recovery, production identity/TLS and an independent deployment review remain required before claiming those profiles. This acceptance harness is a repository fixture, not a general-purpose public MCP launcher API. The temporary executor ledger is in memory; the separate existing durable recovery suite supplies ledger-restart evidence.

## Recorded local validation, 5 November 2026

The [saved acceptance report](../validation/mcp-isolation-2026-11-05.json) passed all 21 checks on macOS arm64 / Node 26.12.0 with the pinned Linux Node 24.22.1 guest image above. It records one approved local write, one approved remote call, seven refused invalid authorization proofs, seven explicit no-dispatch reconciliations and zero redirect leaks. Cleanup completed; no fixture containers or private host staging directories remained after validation.

The full `npm run check`, with both image variables set, passed 787 tests with zero skips and all installed-package consumers. The dedicated macOS platform gate separately passed all 16 tests, including the six required real runtime tests. All nine MCP/platform-verifier tests also passed on Node 22.13.0 with the real container test enabled. Independent review addressed cleanup on failed creation/removal, bounded transport shutdown, reconnect process lifetime, credential/proof binding and strict report metadata/provenance validation. These results measure this local profile and synthetic fixtures only.
