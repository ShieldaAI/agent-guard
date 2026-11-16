# agent-guard-check in a container, built from this repository.
#   docker build -f packages/check/Dockerfile -t agent-guard-check .
#   docker run --rm -v "$PWD:/repo:ro" agent-guard-check
# The image runs as an unprivileged user, needs no network, and reads the mounted repository only.
FROM node:22-alpine AS build
WORKDIR /src
COPY package.json package-lock.json tsconfig.base.json ./
COPY scripts/build.mjs scripts/build.mjs
COPY packages/check/package.json packages/check/package.json
RUN npm ci --ignore-scripts --no-audit --no-fund --workspace packages/check --include-workspace-root
COPY packages/check packages/check
RUN node node_modules/typescript/bin/tsc -p packages/check/tsconfig.json \
 && cd packages/check && npm pack --ignore-scripts --pack-destination /tmp

FROM node:22-alpine
COPY --from=build /tmp/shieldaai-agent-guard-check-*.tgz /tmp/
RUN npm install --global --ignore-scripts --no-audit --no-fund /tmp/shieldaai-agent-guard-check-*.tgz \
 && rm /tmp/shieldaai-agent-guard-check-*.tgz \
 && npm cache clean --force
USER node
WORKDIR /repo
ENTRYPOINT ["agent-guard-check"]
CMD ["."]
