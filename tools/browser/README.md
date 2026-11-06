# Browser verification

The lockfile pins the review tools separately from production dependencies.
From the repository root:

```sh
npm ci --ignore-scripts
npm run build
npm ci --prefix tools/browser --ignore-scripts
tools/browser/node_modules/.bin/playwright install chromium firefox webkit
node apps/agent-ops/check-browser.mjs tools/browser artifacts/browser/chromium/mock chromium
node apps/agent-ops/check-browser-service.mjs tools/browser artifacts/browser/chromium/service chromium
```

Repeat the two browser commands with `firefox` and `webkit`. On a fresh Linux
runner use `playwright install --with-deps` to install the required system
libraries. The fixture creates a disposable local identity provider, certificate
authority and encrypted databases. Its browser-only self-signed certificate
exception does not change the service's OIDC trust or production configuration.
Screenshots and JSON reports belong in ignored `artifacts/`, never company data.

The checks verify keyboard operation, responsive layouts, exact review and
receipt recovery, and automated WCAG 2.1 A/AA rules. They do not replace a
representative human usability study or claim a complete accessibility audit.
