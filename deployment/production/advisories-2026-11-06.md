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
instruction alone is not removal evidence. The build stage updates to checksum-pinned
npm **12.2.2** before installing workspace dependencies. A disposable installation
on Node 24.22.1 and workspace install passed with the lockfile unchanged. Its actual
dependency tree had **zero high/critical findings and two moderate findings**:
[glob](https://github.com/advisories/GHSA-3g3m-2fjr-6pw4) and
[minimatch](https://github.com/advisories/GHSA-g3hv-75wg-m249). These require
attacker-influenced patterns/traversal; the reviewed builder uses a pinned package
lock and disables dependency lifecycle scripts. Applicability to that fixed build
was not demonstrated; the findings remain recorded for update review. None of
this tooling is copied into the runtime. Findings were not dismissed as false
positives or independently shown exploitable through Agent Ops HTTP operations.
Maintainers own the next builder update review: recheck both advisories before
the next release, adopt compatible fixed dependencies when available, and rerun
the locked build and installed-package consumers. A change to the build-input
or lifecycle-script policy requires reassessing these applicability assumptions.

Global npm's Undici 6.28.0 is distinct from Node's embedded Undici 7.30.1.
Separately installed package metadata does not enumerate every component inside
opaque Corepack/Yarn bundles or native Node dependencies. The existing Alpine
audit covers distribution packages, while workspace/browser audits cover their
respective npm trees.

## Python cartography integration

The separately locked Python tree contained `oauthlib@4.0.0`, affected by
[GHSA-3jp2-3mrg-2vxc](https://github.com/oauthlib/oauthlib/security/advisories/GHSA-3jp2-3mrg-2vxc).
The candidate updates only that lock entry to the patched **4.0.1**. Fresh locked
audits using uv 0.13.6 and Python 3.13 report **194 packages, zero vulnerabilities**
for Linux x64/ARM64, macOS ARM64 and Windows x64 selections. Auditing the previous
lock exits unsuccessfully and identifies the advisory, verifying the rejection
path. These are dependency-selection checks, not runtime certification of all
four platforms.

The audit also reports archived `adal@1.2.7`, brought through
`msrestazure`/Cartography. This is a maintenance notice rather than a returned
vulnerability; it is retained without suppression. Maintainers must review its
replacement when updating the upstream Cartography/Azure dependency chain. The
dedicated Python audit workflow checks every PR/main revision and weekly, retains
the exact lock digest and findings, and fails on advisories or lookup failure.
Dependency updater coverage now includes the uv project.

## Final runtime inventory

The reviewed ARM64 production image
`sha256:8b14ec10c087d9b5418610ab7e86e27072fa364d7515073808cb00b1693de303`
contains **36 application package instances: 31 third-party and five workspaces**.
Its fresh npm bulk query returned no published matches. Its Node binary matches
the reviewed base; runtime global package managers are absent. The hosted AMD64
image has the same application-file manifest, while native binaries remain
architecture-specific. This does not resolve the Node prealert or establish the
absence of undisclosed issues.

Machine-readable observations, source URLs/hashes, installed versions, advisory
ranges and the subsequent production-image check are retained under
`artifacts/production-readiness/dependencies/`. The committed
[candidate evidence index](../../docs/validation/production-readiness-2026-11-06.json)
retains compact observations, scope and hashes. This note alone does not attest
a final image.
