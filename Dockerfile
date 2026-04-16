# syntax=docker/dockerfile:1
# Multi-stage build — final image is a minimal scratch container.
# Target binary size: ~15 MB; runtime RAM: 10–50 MB.

# ── Build stage ────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags "-s -w \
              -X main.version=${VERSION} \
              -X main.gitCommit=${GIT_COMMIT} \
              -X main.buildTime=${BUILD_TIME}" \
    -o /aione-agent ./cmd/agent

# ── Final stage ────────────────────────────────────────────────────────────
FROM scratch

# Copy CA certs and timezone data from the builder.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary.
COPY --from=builder /aione-agent /aione-agent

# Default config path; mount your agent.yaml here.
VOLUME ["/etc/aione-agent", "/var/lib/aione-agent"]

# The agent reads its config from -config flag.
ENTRYPOINT ["/aione-agent"]
CMD ["-config", "/etc/aione-agent/agent.yaml"]
