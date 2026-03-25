FROM mysql:9.6.0@sha256:d1e3f7334b4f647e4e659554d4d8af11ffa1aa8cebd6decbcf1eba33aa2f3f40

# Copy validation script
COPY validate-and-start.sh /usr/local/bin/validate-and-start.sh
RUN chmod +x /usr/local/bin/validate-and-start.sh

ARG DVRTC_VERSION=dev
ARG DVRTC_SERVICE=db
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

# Use our validation script as entrypoint wrapper
ENTRYPOINT ["/usr/local/bin/validate-and-start.sh"]
CMD ["mysqld"]
