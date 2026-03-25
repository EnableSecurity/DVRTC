FROM --platform=$BUILDPLATFORM golang:1.23-bookworm AS sipexer-builder
ARG TARGETOS=linux TARGETARCH=amd64
ARG SIPEXER_REF=20d6c6287c5eba623b949eed3c31978ffa1a13ea

# Build sipexer from main branch - v1.2.0 release lacks WS/WSS transport support
# Cross-compile natively to avoid QEMU crashes under emulation
RUN git init /sipexer && \
    cd /sipexer && \
    git remote add origin https://github.com/miconda/sipexer.git && \
    git fetch --depth=1 origin "${SIPEXER_REF}" && \
    git checkout --detach FETCH_HEAD && \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /usr/local/bin/sipexer .

FROM debian:bookworm-slim

ARG DVRTC_VERSION=dev
ARG DVRTC_SERVICE=kamailio
ARG VCS_REF=unknown
ARG KAMAILIO_VERSION=61

LABEL org.opencontainers.image.title="DVRTC ${DVRTC_SERVICE}" \
      org.opencontainers.image.version="${DVRTC_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/enablesecurity/dvrtc"

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    ca-certificates \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/share/dvrtc && cat > /usr/share/dvrtc/version.json <<EOF
{
  "product": "dvrtc",
  "service": "${DVRTC_SERVICE}",
  "version": "${DVRTC_VERSION}",
  "revision": "${VCS_REF}"
}
EOF

# Copy protocols file (required for TCP/UDP protocol lookups)
COPY protocols /etc/protocols

# Add Kamailio repository
RUN wget -qO- https://deb.kamailio.org/kamailiodebkey.gpg | gpg --dearmor -o /usr/share/keyrings/kamailio.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/kamailio.gpg] http://deb.kamailio.org/kamailio${KAMAILIO_VERSION} bookworm main" > /etc/apt/sources.list.d/kamailio.list

# Install Kamailio with required modules
RUN apt-get update && apt-get install -y --no-install-recommends \
    kamailio \
    kamailio-mysql-modules \
    kamailio-tls-modules \
    kamailio-websocket-modules \
    kamailio-utils-modules \
    kamailio-json-modules \
    default-mysql-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/certstore

RUN useradd -u 15000 kamailio || true
RUN mkdir -p /var/run/kamailio/ && chown kamailio /var/run/kamailio

# Copy sipexer binary from builder stage
COPY --from=sipexer-builder /usr/local/bin/sipexer /usr/local/bin/sipexer

COPY config/ /etc/kamailio/

# Copy health check script
COPY --chmod=755 healthcheck/healthcheck.sh /usr/local/bin/kamailio-healthcheck

WORKDIR /opt/run/kamailio

COPY run.sh run.sh

CMD ["./run.sh"]
