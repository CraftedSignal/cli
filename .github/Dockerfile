# syntax=docker/dockerfile:1
# GoReleaser Dockerfile — binary is pre-built and provided in build context

# Prep stage: gather CA certs, timezone data, user/group files
FROM alpine:3.23 AS prep

RUN apk add --no-cache ca-certificates tzdata && \
    mkdir -p /scratch/etc/ssl/certs && \
    cp /etc/ssl/certs/ca-certificates.crt /scratch/etc/ssl/certs/ && \
    mkdir -p /scratch/usr/share && \
    cp -r /usr/share/zoneinfo /scratch/usr/share/ && \
    echo "csctl:x:1000:1000::/app:/sbin/nologin" > /scratch/etc/passwd && \
    echo "csctl:x:1000:" > /scratch/etc/group

# Final stage - scratch for minimal attack surface
FROM scratch

LABEL org.opencontainers.image.source="https://github.com/CraftedSignal/cli"

COPY --from=prep /scratch/usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=prep /scratch/etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=prep /scratch/etc/passwd /etc/passwd
COPY --from=prep /scratch/etc/group /etc/group

# Copy pre-built binary from GoReleaser build context
ARG TARGETPLATFORM
COPY --chmod=755 ${TARGETPLATFORM}/csctl /usr/local/bin/csctl

USER 1000:1000

ENTRYPOINT ["/usr/local/bin/csctl"]
