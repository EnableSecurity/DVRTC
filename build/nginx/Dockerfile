FROM ubuntu:24.04@sha256:67efaecc0031a612cf7bb3c863407018dbbef0a971f62032b77aa542ac8ac0d2

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y nginx libnginx-mod-http-fancyindex curl

COPY config/sites-available/default /etc/nginx/sites-available/default
COPY config/options-ssl-nginx.conf /etc/nginx/options-ssl-nginx.conf
COPY web/ /var/www/html/

# Forward request logs to Docker log collector
RUN ln -sf /dev/stdout /var/log/nginx/access.log \
  && ln -sf /dev/stderr /var/log/nginx/error.log

RUN mkdir /etc/certstore

COPY --chmod=755 healthcheck/healthcheck.sh /usr/local/bin/nginx-healthcheck

STOPSIGNAL SIGTERM

COPY run.sh run.sh

ARG DVRTC_VERSION=dev
ARG DVRTC_SERVICE=nginx
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

CMD [ "./run.sh" ]
