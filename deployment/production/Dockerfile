# Supply an independently reviewed Node image by repository@sha256:digest.
# No mutable base-image default is provided.
ARG NODE_IMAGE
FROM ${NODE_IMAGE} AS build
ARG NODE_IMAGE
WORKDIR /app
RUN node -e 'if (!/^.+@sha256:[a-f0-9]{64}$/.test(process.argv[1])) process.exit(1); const [major, minor, patch] = process.versions.node.split(".").map(Number), floor = {22:[23,4],24:[22,1],26:[12,1]}[major]; if (!floor || minor < floor[0] || minor === floor[0] && patch < floor[1]) throw Error("REVIEWED_SECURITY_PATCHED_NODE_REQUIRED")' "$NODE_IMAGE"
# Checksum-pinned builder update removes the base npm tree's known high findings.
ADD --checksum=sha256:07fecbf753e2c3bc10ebeb3e9ed8738f6a0cc1292998b79e2e9f1dd2a5525e0c https://registry.npmjs.org/npm/-/npm-12.2.2.tgz /tmp/npm.tgz
RUN npm install --global --ignore-scripts --engine-strict --no-audit --no-fund /tmp/npm.tgz && test "$(npm --version)" = 12.2.2 && rm /tmp/npm.tgz
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages ./packages
COPY apps/agent-map ./apps/agent-map
COPY scripts ./scripts
RUN npm ci --ignore-scripts && npm run build && npm prune --omit=dev --ignore-scripts

FROM ${NODE_IMAGE} AS runtime
WORKDIR /app
ENV NODE_ENV=production
# Build tooling is unnecessary in the runtime and has its own transitive attack
# surface. Keep only Node; npm remains confined to the preceding build stage.
RUN rm -rf /usr/local/lib/node_modules /opt/yarn* /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg /usr/local/bin/pnpm /usr/local/bin/pnpx
COPY LICENSE ./LICENSE
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/packages/core/package.json ./packages/core/package.json
COPY --from=build /app/packages/core/dist ./packages/core/dist
COPY --from=build /app/packages/executor/package.json ./packages/executor/package.json
COPY --from=build /app/packages/executor/dist ./packages/executor/dist
COPY --from=build /app/packages/agent-map/package.json ./packages/agent-map/package.json
COPY --from=build /app/packages/agent-map/dist ./packages/agent-map/dist
COPY --from=build /app/packages/mcp/package.json ./packages/mcp/package.json
COPY --from=build /app/packages/mcp/dist ./packages/mcp/dist
COPY --from=build /app/packages/scenarios/package.json ./packages/scenarios/package.json
COPY --from=build /app/packages/scenarios/dist ./packages/scenarios/dist
COPY apps/agent-ops/cli.mjs apps/agent-ops/runtime.mjs apps/agent-ops/server.mjs apps/agent-ops/workflow.mjs apps/agent-ops/limits.mjs apps/agent-ops/onboarding.mjs ./apps/agent-ops/
COPY apps/agent-ops/tls-policy.mjs apps/agent-ops/custody.mjs ./apps/agent-ops/
COPY apps/agent-ops/observability.mjs ./apps/agent-ops/
COPY apps/agent-ops/history-state.mjs apps/agent-ops/history-files.mjs apps/agent-ops/retention.mjs ./apps/agent-ops/
COPY apps/agent-ops/public ./apps/agent-ops/public
COPY deployment/production/healthcheck.mjs deployment/production/verify-maintenance.mjs ./deployment/production/
USER 10001:10001
RUN node apps/agent-ops/cli.mjs --help >/dev/null
EXPOSE 8443
ENTRYPOINT ["node", "apps/agent-ops/cli.mjs"]
CMD ["--config", "/run/agent-ops/config.json"]

# Test-only stage; the default final image excludes identity-provider fixtures.
FROM runtime AS verification
COPY packages/agent-map/test/helpers/oidc-provider.mjs ./packages/agent-map/test/helpers/oidc-provider.mjs
COPY deployment/production/verify-cli.mjs ./deployment/production/verify-cli.mjs

FROM runtime AS production
