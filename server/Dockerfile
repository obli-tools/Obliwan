# ObliWAN server image — Node API + Socket.io, and (from later milestones) the
# CWMP/TR-069 listener, the SNMP trap receiver and the syslog receiver.
# ObliWAN is agentless: there is no Go binary, no MSI and no wizard to build.

# ---- Build stage (shared + server) ----
FROM node:24-alpine AS builder
WORKDIR /app

COPY package.json ./
COPY shared/ ./shared/
RUN cd shared && npm install && npm run build

COPY server/package.json ./server/
RUN cd server && npm install

COPY server/tsconfig.json server/knexfile.ts ./server/
COPY server/src/ ./server/src/
RUN cd server && npm run build

# ---- Production stage ----
FROM node:24-alpine AS production
WORKDIR /app

# openssh-client: the SSH transport (RouterOS /export, DrayTek/Zyxel CLI) and
# SFTP config backups shell out to it.
# wireguard-tools + iproute2: used ONLY by the `obliwan-wg` sidecar, which runs
# this same image as a second compose service (network_mode: host, NET_ADMIN,
# entrypoint dist/src/wgSidecar.js) to bring up the host's WireGuard link to
# the CHR. The server process itself never calls `wg` or `ip`: it generates
# keys in-process and only writes the config file the sidecar reads.
RUN apk add --no-cache openssh-client wireguard-tools iproute2

COPY --from=builder /app/shared/package.json ./shared/
COPY --from=builder /app/shared/dist/ ./shared/dist/

COPY --from=builder /app/server/package.json ./server/
COPY package.json ./
RUN cd server && npm install --omit=dev

# dist/ already holds the compiled knexfile.js and db/migrations/*.js —
# index.ts calls db.migrate.latest() at startup.
COPY --from=builder /app/server/dist/ ./server/dist/

# ┌─ THE BENCH INSTALLER TRAVELS INSIDE THE IMAGE ─────────────────────────────┐
# │ `GET /api/bench/download` resolves `<server>/dist-bench`, so the artefact   │
# │ has to be there for the topbar's "Download app" to do anything. Carrying it │
# │ in the image means deploying a release publishes the matching installer in  │
# │ the same gesture — no volume to remember, and the version the server        │
# │ advertises is necessarily the one it can hand out.                          │
# │                                                                             │
# │ That is why the release script builds and SIGNS the bench BEFORE this image │
# │ (release pipeline, phase 3): an image built first would bake in             │
# │ whatever the previous run left behind, or nothing at all.                   │
# │                                                                             │
# │ COSTS ~120 MB OF IMAGE, and that is the deliberate trade. The directory is  │
# │ kept in git by a `.gitkeep` precisely so this COPY always has a source —    │
# │ Docker fails a COPY whose source is missing, and a fresh clone has never    │
# │ run the bench build. An empty directory simply means the download endpoint  │
# │ reports nothing published, and the button removes itself.                   │
# │                                                                             │
# │ `BENCH_ARTEFACT_DIR` and the compose volume still override this, for        │
# │ publishing a newer installer without rebuilding the server.                 │
# └─────────────────────────────────────────────────────────────────────────────┘
COPY server/dist-bench/ ./server/dist-bench/

COPY server/docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 3001 stays internal to the compose network (nginx proxies it).
EXPOSE 3001/tcp
# Inbound device traffic — these ARE published by the compose files. This is the
# one deviation from the Obli* topology; see docker-compose.yml for the why.
# 162 and 514 are privileged ports: the process runs as root inside the
# container, which is what allows binding them. Do not add a USER directive
# without moving those listeners to high ports and remapping them in compose.
EXPOSE 7547/tcp
EXPOSE 7548/tcp
EXPOSE 162/udp
EXPOSE 514/udp
EXPOSE 514/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD sh -c "wget --no-verbose --tries=1 --spider http://localhost:${PORT:-3001}/health || exit 1"

WORKDIR /app/server
ENTRYPOINT ["/entrypoint.sh"]
CMD ["node", "dist/src/index.js"]
