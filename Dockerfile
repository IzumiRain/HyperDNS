# syntax=docker/dockerfile:1

# ------------------------------------------------------------------------------
# Build Stage
# ------------------------------------------------------------------------------
# The tag floats inside the 1.26 series on purpose: go.mod asks for 1.26.4, and
# when the image happens to carry an older patch the default GOTOOLCHAIN=auto
# fetches the one the module names rather than refusing to build it.
FROM golang:1.26-alpine AS builder

WORKDIR /src

# ca-certificates is for the module fetch; git is what the module proxy needs for
# any dependency it cannot serve as a zip.
RUN apk add --no-cache git ca-certificates

# Copied first and on their own so the module download is cached against these two
# files rather than against every source edit.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 is what makes the result runnable on a distroless or scratch base
# and on a VPS with no matching libc. -trimpath keeps the build path out of the
# binary, so two people building the same commit get the same bytes.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/hyperdns ./cmd/hyperdns

# ------------------------------------------------------------------------------
# Final Runtime Stage
# ------------------------------------------------------------------------------
FROM alpine:3.20

WORKDIR /app

# ca-certificates: the ACME client and the outbound public-IP probe both need a
# trust store. tzdata: expiry timestamps and quota cycles are rendered in the
# operator's zone, and without this every container is UTC whatever TZ says.
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /out/hyperdns /app/hyperdns

# Created here as well as declared below, so a run with no bind mount still has
# somewhere to put the key: the master key is written before anything else, and a
# missing directory there is a fatal start rather than a warning.
RUN mkdir -p /app/data /app/certs

# DNS (53), SNI proxy (80/443), DoT (853), dashboard (8080) and HTTPS/DoH (8443).
# Decorative under `network_mode: host`, which is what docker-compose.yml uses.
EXPOSE 53/udp 53/tcp 80/tcp 443/tcp 853/tcp 8080/tcp 8443/tcp

VOLUME ["/app/data", "/app/certs"]

# Reports the daemon as unhealthy while the dashboard mux is not answering. The
# port is a variable because web_port is an operator setting: a health check that
# hardcodes 8080 reports a container as sick for the sole reason that its owner
# moved the dashboard. /api/v1/version needs no key and is GET/HEAD only, and the
# request arrives from 127.0.0.1, which passes the api_bind peer-address gate.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${HYPERDNS_HEALTH_PORT:-8080}/api/v1/version" || exit 1

# -daemon is not optional here, for the same reason scripts/hyperdns.service passes
# it: a container must never be left guessing whether it is a server. `docker run -d`
# and `docker compose up -d` both hand the process /dev/null on stdin, and /dev/null
# is a character device, so the old "is stdin a terminal?" heuristic answered yes,
# started the interactive menu, read EOF and exited. The container came up, printed
# the menu, and died inside a second. The heuristic is fixed too — but a deployment
# entry point has no business depending on a heuristic at all.
#
# -db and -key are passed explicitly, and this is not a style choice. Without them
# the daemon resolves both relative to the working directory — /opt/hyperdns does
# not exist in this image, so it falls back to ./data.db and ./master.key — which
# puts them in /app, inside the container's writable layer and outside the volume
# declared right above. `docker compose up --build`, or anything else that
# recreates the container, would then start against an empty database *and* a
# freshly generated master key: every subscriber, the admin password and the API
# key gone, and the previous data.db no longer decryptable even if a copy of it
# survived. All three persistent artefacts belong under /app/data.
ENTRYPOINT ["/app/hyperdns", "-daemon", \
    "-config", "/app/data/config.json", \
    "-db", "/app/data/data.db", \
    "-key", "/app/data/master.key"]
