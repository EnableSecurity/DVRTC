FROM debian:bookworm-slim

ARG RTPPROXY_VERSION=3.2.0

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    iproute2 \
    netcat-openbsd \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install the upstream Debian 12 package for the latest rtpproxy release
# instead of compiling from source in-image.
RUN tmpdir="$(mktemp -d)" && \
    cd "$tmpdir" && \
    curl -fsSLO "https://github.com/sippy/rtpproxy/releases/download/v${RTPPROXY_VERSION}/debian-12_packages.zip" && \
    unzip -q debian-12_packages.zip "rtpproxy_*_amd64.deb" && \
    apt-get update && \
    apt-get install -y ./rtpproxy_*_amd64.deb && \
    rm -rf "$tmpdir" /var/lib/apt/lists/*

RUN useradd -u 15004 rtpproxy || usermod -u 15004 rtpproxy || true
RUN mkdir -p /var/run/rtpproxy /var/log/rtpproxy /opt/run/rtpproxy /recordings/spool \
    && chown -R rtpproxy:rtpproxy /var/run/rtpproxy /var/log/rtpproxy /opt/run/rtpproxy /recordings

WORKDIR /opt/run/rtpproxy

COPY run.sh run.sh
COPY --chmod=755 healthcheck/healthcheck.sh /usr/local/bin/rtpproxy-healthcheck
RUN chmod +x run.sh && chown rtpproxy:rtpproxy run.sh

ARG DVRTC_VERSION=dev
ARG DVRTC_SERVICE=rtpproxy
ARG VCS_REF=unknown
ARG DVRTC_SOURCE=https://github.com/EnableSecurity/DVRTC

LABEL org.opencontainers.image.title="DVRTC ${DVRTC_SERVICE}" \
      org.opencontainers.image.version="${DVRTC_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="${DVRTC_SOURCE}"

RUN mkdir -p /usr/share/dvrtc && cat > /usr/share/dvrtc/version.json <<EOF
{
  "product": "dvrtc",
  "service": "${DVRTC_SERVICE}",
  "version": "${DVRTC_VERSION}",
  "revision": "${VCS_REF}"
}
EOF

USER rtpproxy

CMD ["./run.sh"]
