FROM debian:bookworm-slim
ARG RTPENGINE_VERSION=14.1.1.5
ARG RTPENGINE_REPO_REL=14.1
ARG RTPENGINE_KEYRING_DEB=rtpengine-dfx-repo-keyring_1.0_all.deb
ARG RTPENGINE_KEYRING_SHA256=78fe26f0251138f4e3c749c88dc4df29666c8efe0823858d3a4ab49d2fa2e088

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    ca-certificates \
    dpkg \
    && rm -rf /var/lib/apt/lists/*

# Install the upstream repo keyring, verify its published checksum, and use
# the repository with apt signature verification enabled.
RUN wget -q "https://rtpengine.dfx.at/latest/pool/main/r/rtpengine-dfx-repo-keyring/${RTPENGINE_KEYRING_DEB}" \
        -O "/tmp/${RTPENGINE_KEYRING_DEB}" \
    && echo "${RTPENGINE_KEYRING_SHA256}  /tmp/${RTPENGINE_KEYRING_DEB}" | sha256sum -c - \
    && dpkg -i "/tmp/${RTPENGINE_KEYRING_DEB}" \
    && rm -f "/tmp/${RTPENGINE_KEYRING_DEB}" \
    && echo "deb [signed-by=/usr/share/keyrings/dfx.at-rtpengine-archive-keyring.gpg] https://rtpengine.dfx.at/${RTPENGINE_REPO_REL} bookworm main" > /etc/apt/sources.list.d/rtpengine.list

# Create required directory for rtpengine post-install script
RUN mkdir -p /etc/modprobe.d

RUN apt-get update && apt-get install -y --no-install-recommends \
    rtpengine-daemon \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -u 15004 rtpengine || true
RUN mkdir -p /opt/run/rtpengine /var/log/rtpengine && chown -R rtpengine /opt/run/rtpengine /var/log/rtpengine

COPY --chmod=755 healthcheck/healthcheck.sh /usr/local/bin/rtpengine-healthcheck
COPY --chmod=755 --chown=rtpengine:rtpengine run.sh /opt/run/rtpengine/run.sh

ARG DVRTC_VERSION=dev
ARG DVRTC_SERVICE=rtpengine
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

USER rtpengine

WORKDIR /opt/run/rtpengine

CMD ["./run.sh"]
