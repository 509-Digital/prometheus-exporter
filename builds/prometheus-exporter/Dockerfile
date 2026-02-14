# Kubescape Prometheus Exporter - Custom fork with per-control metrics
# Built from local source (COPY-based for Kaniko compatibility)
# Exposes per-control compliance status as Prometheus metrics (Tier 2)

# ============================================
# Stage 1: Build Go binary
# ============================================
FROM harbor.509.digital/proxy-docker-hub/library/golang:1.25-bookworm AS builder

ARG COMMIT_SHA
ARG VERSION

ENV GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64

WORKDIR /work

# Copy dependency files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and build
COPY . .
RUN go build -o /out/prometheus-exporter .

# ============================================
# Stage 2: Minimal runtime image
# ============================================
FROM gcr.io/distroless/static-debian12:nonroot

ARG COMMIT_SHA
ARG VERSION

LABEL org.opencontainers.image.source="https://github.com/509-Digital/prometheus-exporter"
LABEL org.opencontainers.image.revision="${COMMIT_SHA}"
LABEL org.opencontainers.image.description="Kubescape prometheus-exporter with per-control metrics"

USER nonroot
WORKDIR /home/nonroot/

COPY --from=builder /out/prometheus-exporter /usr/bin/prometheus-exporter

ENV RELEASE=${VERSION}

ENTRYPOINT ["prometheus-exporter"]
