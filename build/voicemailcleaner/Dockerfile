FROM alpine:3.23.3@sha256:59855d3dceb3ae53991193bd03301e082b2a7faa56a514b03527ae0ec2ce3a95

ARG DVRTC_VERSION=dev
ARG DVRTC_SERVICE=voicemailcleaner
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="DVRTC ${DVRTC_SERVICE}" \
      org.opencontainers.image.version="${DVRTC_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/enablesecurity/dvrtc"

RUN apk add python3
RUN apk add shadow
RUN useradd -u 100 asterisk

RUN mkdir -p /usr/share/dvrtc && cat > /usr/share/dvrtc/version.json <<EOF
{
  "product": "dvrtc",
  "service": "${DVRTC_SERVICE}",
  "version": "${DVRTC_VERSION}",
  "revision": "${VCS_REF}"
}
EOF

USER asterisk

COPY voicemail_cleaner.py voicemail_cleaner.py

CMD ["python3", "voicemail_cleaner.py"]
