FROM debian:sid-slim

ARG DVRTC_VERSION=dev
ARG DVRTC_SERVICE=asterisk
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="DVRTC ${DVRTC_SERVICE}" \
      org.opencontainers.image.version="${DVRTC_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/enablesecurity/dvrtc"

RUN apt-get update && apt-get install -y --no-install-recommends \
    asterisk \
    asterisk-modules \
    asterisk-core-sounds-en \
    asterisk-moh-opsound-wav \
    libopus0 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/share/dvrtc && cat > /usr/share/dvrtc/version.json <<EOF
{
  "product": "dvrtc",
  "service": "${DVRTC_SERVICE}",
  "version": "${DVRTC_VERSION}",
  "revision": "${VCS_REF}"
}
EOF

# Create asterisk user with UID 100 (must match voicemailcleaner)
# May already exist from package, so ignore failures
RUN useradd -u 100 asterisk || usermod -u 100 asterisk || true

# Copy configuration files
COPY config/ /etc/asterisk/
RUN mkdir -p /var/lib/asterisk-config-template && \
    cp /etc/asterisk/pjsip.conf /var/lib/asterisk-config-template/pjsip.conf

# Copy health check script
COPY --chmod=755 healthcheck/healthcheck.sh /usr/local/bin/asterisk-healthcheck

WORKDIR /opt/run/asterisk

COPY run.sh run.sh

CMD ["./run.sh"]
