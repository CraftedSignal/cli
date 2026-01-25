# syntax=docker/dockerfile:1

# Build stage
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary with static linking
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o csctl ./cmd/csctl

# Prepare files for scratch image
RUN mkdir -p /scratch/etc/ssl/certs && \
    cp /etc/ssl/certs/ca-certificates.crt /scratch/etc/ssl/certs/ && \
    mkdir -p /scratch/usr/share && \
    cp -r /usr/share/zoneinfo /scratch/usr/share/ && \
    echo "csctl:x:1000:1000::/app:/sbin/nologin" > /scratch/etc/passwd && \
    echo "csctl:x:1000:" > /scratch/etc/group

# Final stage - scratch for minimal attack surface
FROM scratch

LABEL org.opencontainers.image.source="https://github.com/craftedsignal/cli"

# Copy timezone data
COPY --from=builder /scratch/usr/share/zoneinfo /usr/share/zoneinfo

# Copy CA certificates for HTTPS
COPY --from=builder /scratch/etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy user/group files for non-root execution
COPY --from=builder /scratch/etc/passwd /etc/passwd
COPY --from=builder /scratch/etc/group /etc/group

# Copy binary
COPY --from=builder /app/csctl /usr/local/bin/csctl

# Switch to non-root user
USER 1000:1000

# Default entrypoint
ENTRYPOINT ["/usr/local/bin/csctl"]
