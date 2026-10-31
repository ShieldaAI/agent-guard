# Viewer asset boundary review

Date: 30 October 2026. This focused audit found and corrected a shared startup
race in the reference HTTP and identity HTTPS asset loaders. Final validation of
the rebuilt distribution and the full repository suite remains pending; the
checks below do not replace that gate or establish company deployment readiness.

## Reproduction

Both loaders checked each public asset with `lstat(path)` and then read it using
`readFile(path)`. Isolated processes deterministically mutated a temporary
`index.html` between those operations:

- Growing the file caused each transport to materialize **8,388,616 bytes**
  before rejecting the asset's **4,194,304-byte** limit.
- Replacing it with a named pipe hung both startup paths until their isolated
  process deadline terminated them.
- Replacing it with a symlink bypassed the existing symlink rejection. The HTTP
  server accepted the replacement and served a synthetic private canary at `/`.

These cases require access to mutate the configured asset directory during
startup. They are not remote HTTP-only attacks. All fixtures and canaries were
created for the test; no user secrets or external identity provider were used.

## Correction

The shared [asset loader](../../../packages/agent-map/src/assets.ts) opens each
fixed leaf with nonblocking and no-follow flags, checks the opened descriptor for
a regular file, reads at most **4 MiB plus one byte**, and closes that descriptor
on success or failure. Both transports now use it before their listener starts.
Accepted bytes are copied into the startup cache without retaining the full
maximum allocation for a small file. A later pathname replacement cannot redirect
that descriptor to another file.

This protection applies to the fixed leaf entries. Ancestor-directory ownership
and provisioning remain host responsibilities. Configured asset hosting requires
both file-open capabilities and fails with `MAP_CONFIG_INVALID` if unavailable;
API startup without `viewerDirectory` is unchanged. The package guide documents
the POSIX pilot requirement.

Ten named [regressions](../../../packages/agent-map/test/asset-input.test.mjs)
exercise both HTTP and HTTPS: growth after descriptor inspection, pre-open symlink
replacement, FIFO replacement, exact-limit cached content/CSP, and retaining the
opened regular file after its path is replaced. Child processes have a five-second
deadline so a FIFO regression cannot hang the test runner. Successful HTTPS cases
use a disposable local CA and identity-provider fixture with explicit certificate
verification. Unsupported hosts assert safe rejection before POSIX fixture setup;
this session exercised the supported macOS cases, not native Windows.

## Focused verification

- Before the correction, the existing HTTP/service/identity/viewer subset passed
  **160 tests**; the adversarial startup probes above exposed the missing cases.
- After the correction, that subset plus the new cases passed **170 tests** in
  **9.318 seconds**, with zero failures or skips.
- The fixed runtime check used Node's TypeScript stripping and a temporary
  module-resolution hook for only `assets.ts`, `http.ts` and `identity-http.ts`;
  unchanged modules used the existing distribution. No build output was changed.
- `tsc --project packages/agent-map/tsconfig.json --noEmit`, syntax checks of the
  new JavaScript fixtures, and `git diff --check` passed.
- A separate internal reviewer found no correctness or test blocker in the
  descriptor handling, bounds, transport composition or regressions.

The normal `npm run check` and full-suite results must be recorded after building
the distribution. This focused pass did not start Neo4j or contact AWS or a
company identity provider.
