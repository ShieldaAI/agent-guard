# Browser dependency acquisition

The Ubuntu 24.04 runner pin makes the browser host predictable; it did not remove
the observed package-download bottleneck. In CI run
[42142732668](https://github.com/ShieldaAI/agent-guard/actions/runs/42142732668),
Chromium job 127646754467 fetched package indexes quickly, but 21.1 MB of font
packages from `azure.archive.ubuntu.com` took 8 minutes 38 seconds at 40.7 kB/s.
The Playwright browser downloads then finished in about eight seconds and all
three Chromium suites passed. WebKit also passed. Firefox subsequently fetched
48.8 MB in 18 minutes 21 seconds at 44.4 kB/s, then passed all three suites.
[The run evidence](ci-53acbde.json) records all nine passing suite gates and 156
accessibility snapshots. The current run succeeded; the slow dependency
transport left little margin within the existing 20-minute job limit.

The browser job now selects `https://archive.ubuntu.com/ubuntu/` through the
runner's existing mirror list. It first checks Ubuntu 24.04/amd64, the expected
mirror-list indirection, the Ubuntu archive `Signed-By` field, and the reviewed
three-entry mirror list. An unexpected runner configuration fails with a clear
message. It does not modify repository suites, components, signing keys or APT
security options. The Ubuntu runner pin, three engines, test commands, evidence
uploads and 20-minute job timeout remain unchanged. This avoids the observed
Azure endpoint; it is not a guarantee against all network failures. A successful
subsequent hosted run is required to validate acquisition on the new candidate.

The expected mirror list and indirection were checked against the official
[runner source for image ubuntu24/20261101.360](https://github.com/actions/runner-images/blob/ubuntu24/20261101.360/images/ubuntu/scripts/build/configure-apt-sources.sh).
Ubuntu documents the archive repository and its signing-key binding in its
[package-management guide](https://ubuntu.com/server/docs/how-to/software/package-management/).
The runner's [APT configuration](https://github.com/actions/runner-images/blob/main/images/ubuntu/scripts/build/configure-apt.sh)
uses network timeouts, but the observed slowly progressing transfer completed
without triggering failover. No test was skipped to hide that delay.

Local validation parsed the workflow YAML and checked Bash/Python syntax. A
temporary fixture exercised the reviewed configuration and four refusals
(different OS version, signing key, mirror list and architecture); each refusal
left the mirror file untouched, and the successful case preserved source-file
bytes. Removing the added step yields the same parsed workflow as `53acbde`,
including every existing gate and timeout. These are configuration checks,
not a claim that the replacement mirror has already passed hosted acquisition.
