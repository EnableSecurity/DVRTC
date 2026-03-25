FROM debian:bookworm-slim

ARG DVRTC_VERSION=dev
ARG DVRTC_SERVICE=dbcleaner
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="DVRTC ${DVRTC_SERVICE}" \
      org.opencontainers.image.version="${DVRTC_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/enablesecurity/dvrtc"

RUN apt-get update && apt-get install -y --no-install-recommends \
    default-mysql-client \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/share/dvrtc && cat > /usr/share/dvrtc/version.json <<EOF
{
  "product": "dvrtc",
  "service": "${DVRTC_SERVICE}",
  "version": "${DVRTC_VERSION}",
  "revision": "${VCS_REF}"
}
EOF

COPY run.sh /run.sh
ENTRYPOINT [ "/run.sh" ]
