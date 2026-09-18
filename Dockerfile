# Build Stage
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o hyperdns ./cmd/hyperdns

# Final Runtime Stage
FROM alpine:3.20

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /app/hyperdns /app/hyperdns

# Expose DNS, Web, DoH, DoT, and SNI Proxy ports
EXPOSE 53/udp 53/tcp 80/tcp 443/tcp 853/tcp 8080/tcp 8443/tcp

VOLUME ["/app/data", "/app/certs"]

ENTRYPOINT ["/app/hyperdns", "-config", "/app/data/config.json"]
