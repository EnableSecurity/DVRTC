FROM debian:bookworm-slim

ARG OPENSIPS_VERSION=3.6

RUN apt-get update && apt-get install -y --no-install-recommends \
    gnupg2 \
    wget \
    ca-certificates \
    netcat-openbsd \
    netbase \
    && rm -rf /var/lib/apt/lists/*

# Add OpenSIPS repository
RUN wget -qO - https://apt.opensips.org/pubkey.gpg | apt-key add -
RUN echo "deb https://apt.opensips.org bookworm ${OPENSIPS_VERSION}-releases" > /etc/apt/sources.list.d/opensips.list

RUN apt-get update && apt-get install -y --no-install-recommends \
    opensips \
    opensips-tls-module \
    opensips-tls-openssl-module \
    opensips-tlsmgm-module \
    opensips-auth-modules \
    opensips-regex-module \
    && rm -rf /var/lib/apt/lists/*

# Create opensips user if not exists
RUN id opensips 2>/dev/null || useradd -u 15002 opensips
RUN mkdir -p /var/run/opensips /var/log/opensips \
    && chown -R opensips:opensips /var/run/opensips /var/log/opensips
RUN mkdir -p /etc/certstore

WORKDIR /etc/opensips

# Copy configuration files
COPY config/ /etc/opensips/

RUN mkdir -p /opt && chown -R opensips:opensips /etc/opensips

COPY --chmod=755 healthcheck/healthcheck.sh /usr/local/bin/opensips-healthcheck
COPY run.sh /opt/run.sh
RUN chmod +x /opt/run.sh && chown opensips:opensips /opt/run.sh

ARG DVRTC_VERSION=dev
ARG DVRTC_SERVICE=opensips
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

USER opensips

CMD ["/opt/run.sh"]
