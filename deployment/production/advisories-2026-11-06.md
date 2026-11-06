# Runtime advisory review · 6 November 2026

This is a dated evidence review, not a claim that the complete environment has
zero vulnerabilities. Recheck advisories when selecting a deployment image.

The reviewed base is
`node@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53`.
A read-only Linux/arm64 container measured Node **24.22.1**, npm **11.19.1**,
Corepack **0.36.0** and Yarn **1.22.22**. Node 24.22.1 is the October security
release; the official index also lists the newer nonsecurity patch 24.22.2.
The pinned version must not be described as the newest 24.x patch.
[Node release notes](https://nodejs.org/en/blog/release/v24.22.1).

## Open Node security prealert

The official Node announcement identifies the 22.x, 24.x and 26.x lines for a
security update expected on 11 November 2026 or shortly afterward, with a maximum
announced severity of **HIGH**. At this review, the notice does not disclose
individual issues, affected features or fixed versions. Applicability to this
application is **unassessed**; neither non-applicability nor complete mitigation
can be established from that notice. Removing package managers does not resolve
this Node advisory.
[Official prealert](https://raw.githubusercontent.com/nodejs/nodejs.org/main/apps/site/pages/en/blog/vulnerability/november-2026-security-releases.md).

Review the final advisory when published, select a reviewed immutable replacement
image with applicable fixes, and repeat dependency, installed-package and Linux
recovery checks before updating production. Keep this prealert open until that
review is recorded; do not infer clearance from an empty npm or Alpine scan.

## Global package-manager findings

The npm registry bulk endpoint returned **19 matching advisories** for the
installed global npm dependency tree: **6 high, 12 moderate and 1 low**.
Exact version/range checks identified `brace-expansion@5.0.9`, `glob@13.0.6`,
`ip-address@10.5.0`, `minimatch@10.2.5`, `postcss-selector-parser@7.1.4` and
`undici@6.28.0`. No private package names, credentials or company data were sent.
[npm audit protocol](https://docs.npmjs.com/cli/v11/commands/npm-audit/#bulk-advisory-endpoint).

The production runtime build removes unused global package managers. Its actual
image must be checked for absent package files and command shims; a Dockerfile
instruction alone is not removal evidence. The build stage still uses npm and
retains its separate advisory scope. These findings were not dismissed as false
positives or independently shown exploitable through Agent Ops HTTP operations.

Global npm's Undici 6.28.0 is distinct from Node's embedded Undici 7.30.1.
Separately installed package metadata does not enumerate every component inside
opaque Corepack/Yarn bundles or native Node dependencies. The existing Alpine
audit covers distribution packages, while workspace/browser audits cover their
respective npm trees.

Machine-readable observations, source URLs/hashes, installed versions, advisory
ranges and the subsequent production-image check are retained under
`artifacts/production-readiness/dependencies/`. They must be included with the
candidate evidence; this note alone does not attest a final image.
