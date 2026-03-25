FROM alpine:3.23.3@sha256:59855d3dceb3ae53991193bd03301e082b2a7faa56a514b03527ae0ec2ce3a95

ARG DVRTC_VERSION=dev
ARG DVRTC_SERVICE=unknown
ARG VCS_REF=unknown
ARG TARGET_IMAGE=unknown

LABEL org.opencontainers.image.title="DVRTC ${DVRTC_SERVICE} latest stub" \
      org.opencontainers.image.version="${DVRTC_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/enablesecurity/dvrtc"

ENV DVRTC_VERSION="${DVRTC_VERSION}" \
    DVRTC_SERVICE="${DVRTC_SERVICE}" \
    TARGET_IMAGE="${TARGET_IMAGE}"

RUN mkdir -p /usr/share/dvrtc && cat > /usr/share/dvrtc/version.json <<EOF
{
  "product": "dvrtc",
  "service": "${DVRTC_SERVICE}",
  "version": "${DVRTC_VERSION}",
  "revision": "${VCS_REF}"
}
EOF

COPY --chmod=755 entrypoint.sh /usr/local/bin/latest-stub

ENTRYPOINT ["/usr/local/bin/latest-stub"]
