# CodeQL candidate review · 6 November 2026

CodeQL's successful job status means analysis completed; it does not mean no
alerts exist. The first PR #8 analysis of `edc4972` produced five new alerts and
included an existing package-check alert. Each was reviewed separately.

| Alert | Review and action |
| --- | --- |
| #20 · Remote property injection | Pagination already allowed only `offset` and `limit`. Replace dynamic writes with literal-key branches and test unknown, reserved, duplicate and malformed query parameters on both endpoints. |
| #19 · File-system race | Keep the snapshot's creation descriptor through synchronization instead of closing and reopening its path. Separately strengthen preservation and exclusive publication of damaged recovery files. Current analysis must verify the final implementation. |
| #18 / #21 · File data in HTTP request | Reviewed false positives and dismissed with rationale. The destination is literal loopback, the path is fixed, and only the validated **public** origin supplies Host/SNI. Credentials and configuration contents are not transmitted. Certificate bytes are local TLS trust/pin inputs, not request payloads. The numeric port is bounded. Hostname and wrong-peer tests fail before HTTP dispatch. #21 is the follow-up dataflow through the newly verified TLS options. |
| #17 · Certificate verification disabled | The original probe validated and pinned the exact configured leaf. Strengthen it to use TLS certificate verification with only that certificate as a trust anchor, explicit hostname verification and the exact leaf pin. A different same-host certificate must fail before the HTTP request. |
| #16 · Test code construction | Replace constructed fault-worker source with an explicit worker and structured arguments; retain native crash-phase assertions. |
| #15 · Package-check command selection | Remove environment-derived executable selection from installed-package validation while preserving cross-platform package-manager checks. |
| #22 · npm manifest read race | Read the bounded manifest from one held descriptor after inspecting that descriptor; do not stat and reopen the path. The Node installation remains an explicit build trust boundary. |

This record does not assert that subsequent CodeQL alerts have cleared. The
final analysis and open-alert query must be attributed to the reviewed revision.
No alert is cleared solely because functional tests passed.
