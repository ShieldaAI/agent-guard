# Check that a containerized MCP server is isolated

Read this if you run Model Context Protocol (MCP) servers that you do not control inside the executor's Docker sandbox and need to confirm, on your own host, that such a server cannot reach the network, host files or credentials. Library users can skip it.

## What you will achieve

You will run one script that starts a test MCP server inside a locked-down Linux container, sends it scripted requests through the MCP adapter and the executor, and writes a JSON report with 21 named checks.

The script uses made-up data and temporary files only. It does not pull an image, read your credentials or contact any outside service. It sends scripted requests rather than asking a model, so it shows what the host enforces. It does not measure how often a model is misled.

## Prerequisites

- Node.js 22.13 or newer and a clone of this repository with dependencies installed (`npm ci`).
- Docker with a Linux daemon running. Docker Desktop on macOS or Windows counts: the container runs in its Linux virtual machine.
- A Node.js Linux image that you have reviewed and already pulled, named by digest (`name@sha256:` followed by 64 hex characters). The script rejects tags such as `node:24`. A Node.js image is required because the test server is a JavaScript program.

To find the digest of an image you have pulled:

```sh
docker image inspect --format '{{index .RepoDigests 0}}' node:24
```

## Steps

1. Set the image and run the check from the repository root. The command builds the packages first.

   ```sh
   mkdir -p artifacts
   export AGENT_GUARD_MCP_ISOLATION_IMAGE='node@sha256:YOUR_REVIEWED_DIGEST'
   npm run verify:mcp-isolation -- --output artifacts/mcp-isolation.json
   ```

   Without `--output` the report goes to standard output, after npm's build messages. To get JSON only, build once with `npm run build` and then call `node scripts/verify-mcp-isolation.mjs`.

2. Optional: make the script confirm which host it ran on. Set `AGENT_GUARD_EXPECTED_HOST` to exactly `Linux`, `macOS` or `Windows` before the command. A mismatch fails the run.

3. Optional: run the same check as a test, or together with the executor's other real-container tests.

   ```sh
   npm run build
   AGENT_GUARD_MCP_ISOLATION_IMAGE='node@sha256:YOUR_REVIEWED_DIGEST' \
     node --test scripts/mcp-isolation.test.mjs

   # All real-container tests. Also needs a reviewed shell image and the host name.
   AGENT_GUARD_SANDBOX_IMAGE='alpine@sha256:YOUR_REVIEWED_DIGEST' \
   AGENT_GUARD_MCP_ISOLATION_IMAGE='node@sha256:YOUR_REVIEWED_DIGEST' \
   AGENT_GUARD_EXPECTED_HOST='macOS' node scripts/verify-platform.mjs
   ```

   Without `AGENT_GUARD_MCP_ISOLATION_IMAGE`, the container test in `scripts/mcp-isolation.test.mjs` is skipped. `scripts/verify-platform.mjs` writes its own report to `artifacts/platform-evidence.json` and fails if any test is skipped.

## What you should see

The command exits with one of three codes.

| Exit code | Meaning |
| --- | --- |
| `0` | All 21 checks passed and everything was cleaned up. |
| `1` | A check failed, or Docker or the image was unavailable. The report is still written. |
| `2` | The options were invalid or the report could not be written. |

A passing report has `"passed": true`, `"cleanup": true` and one entry in `checks` for each name below.

| Check | What it confirms |
| --- | --- |
| `runtime-image` | The pinned image is installed locally and runs Node.js. |
| `guest-isolation` | The container has no network (loopback only, and an outbound connection fails), a read-only root filesystem, user ID 1000, no Linux capabilities, `no-new-privileges`, seccomp, and one read-only mount. |
| `host-secret-custody` | A secret file on the host, a host credential variable and the Docker socket are not visible inside the container. |
| `foreign-tenant-before-dispatch` | A request for another tenant is refused before anything reaches the server. |
| `approval-before-dispatch` | A write without approval never reaches the server. |
| `approved-effect` | One approved write reaches the server and creates the expected file in the container. |
| `metadata-quarantine` | When the server changes its tool descriptions, the connection is quarantined and calls prepared earlier cannot run. |
| `reviewed-refresh` | After a refresh, the tools must be reviewed again before any call is accepted. |
| `reconnect-invalidates-work` | Reconnecting removes the old container and starts a new one. Prepared calls and tool reviews from the old session do not carry over. |
| `revocation-before-dispatch` | A revoked task sends nothing. |
| `inflight-unknown-no-replay` | Revoking a task while a call hangs records the call as `UNKNOWN`, keeps its budget reserved and does not send it again. |
| `unknown-reconciliation` | The host settles that `UNKNOWN` call after the container is removed, and the reservation is released. |
| `bounded-stdio` | Oversized output from the server closes the connection instead of filling memory. |
| `remote-approved-dispatch` | An approved call sent over loopback HTTP, through a gateway that holds the credential, reaches the server once. |
| `remote-credential-custody` | The bearer token stays at the gateway. It is absent from the container's environment, from results and from traces, and a wrong token is rejected. |
| `remote-claim-binding` | Seven altered authorization proofs (wrong issuer, audience, subject, scope, expiry, signature or credential fingerprint) are each refused before any HTTP request. |
| `remote-refresh-review` | Restoring a valid proof does not restore the earlier tool review. A refresh and a new review are required. |
| `remote-redirect-no-forward` | A redirect does not forward the token or the request body to another address. |
| `remote-private-address-denied` | A fetch to a private address that was not allowed reaches nothing. |
| `trace-privacy` | Decision traces contain no secret, token, host path or task ID. |
| `cleanup` | The test containers and the temporary host directory are gone. |

The report also records the image, the host platform and Node.js version, the Node.js version inside the container (`guestNode`), SHA-256 hashes of the script and the test server, and these counts: `local.approvedWrites` (1), `remote.approvedCalls` (1), `remote.redirectLeaks` (0), `remote.claimDenials` (7) and `remote.reconciledAuthFailures` (7). It contains no credentials, transcripts, task IDs or file contents.

One behavior is worth knowing before you read your own logs. Some host authorization checks run inside the tool handler, after the executor has already accepted the call. When such a check fails, the call is recorded as `UNKNOWN` even though nothing was sent, and the host has to settle it. The script does that only after it has confirmed that nothing was sent or has removed the container. Nothing is retried automatically.

## What can go wrong

| Symptom | Cause | Fix |
| --- | --- | --- |
| `failure.code` is `PINNED_NODE_IMAGE_REQUIRED` | `AGENT_GUARD_MCP_ISOLATION_IMAGE` is unset or is not a `name@sha256:...` reference. | Set it to the digest of your reviewed image. |
| `failure.code` is `EXPECTED_HOST_MISMATCH` | `AGENT_GUARD_EXPECTED_HOST` does not match the machine, or is not one of the three exact names. | Correct or unset the variable. |
| `failure.stage` is `runtime-image` | Docker is not running, the image is not installed locally, the daemon is not Linux, or the image has no `node` binary. | Start Docker, pull and review the image, then run again. The script never pulls. |
| `failure.code` is `GUEST_ISOLATION_FAILED` or `LAUNCH_PROFILE_FAILED` | The container did not get the expected restrictions, for example because the Docker daemon overrides them. | Inspect the daemon configuration. Do not run servers you do not control on this host until the check passes. |
| `"cleanup": false`, with container names under `cleanupFailures` | A test container could not be removed. | Remove the named containers with `docker rm -f`, then run again. |
| Exit code `2` and a one-line message | An option other than `--output PATH` was given, or the output directory does not exist. | Create the directory and pass only `--output`. |

## Limits

The check uses a test server, a test credential gateway and a test signing key. It does not exercise a real identity provider, TLS, token refresh or your own MCP server. A pass on macOS or Windows covers Docker's Linux virtual machine on that host and says nothing about a native Linux host; run the check on each kind of host you deploy to. The ledger in this check is in memory, so it does not cover recovery after a restart.

For the isolation an MCP server needs in production, and for general limits, see [Support and limits](../support-and-limits.md).
