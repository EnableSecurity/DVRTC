FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    baresip-core \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Create baresip user
RUN useradd -u 15010 -m baresip

# Copy configuration files
COPY --chown=baresip:baresip config /home/baresip/.baresip/config
COPY --chown=baresip:baresip accounts /home/baresip/.baresip/accounts
RUN cp /home/baresip/.baresip/accounts /home/baresip/.baresip/accounts.template

# Copy sound files for RTP bleed demo
COPY --chown=baresip:baresip sounds/ /home/baresip/sounds/

# Copy call generation script
COPY --chown=baresip:baresip callgen.sh /home/baresip/callgen.sh

ARG DVRTC_VERSION=dev
ARG DVRTC_SERVICE=baresip-callgen
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

USER baresip
WORKDIR /home/baresip

CMD ["/bin/sh", "/home/baresip/callgen.sh"]
