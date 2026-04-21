FROM python:3.11-slim AS john-builder

ENV DEBIAN_FRONTEND=noninteractive
ARG JOHN_REF=b2cbb7da85c9652e1df1e37f2691647bd6bfc0de

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        build-essential \
        autoconf \
        automake \
        libtool \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# JtR does not expose a documented per-format configure flag such as
# --enable-formats=sip, so build a lean SIP-capable binary by disabling
# unrelated subsystems we do not use in the testing image. Force x86-64's
# SSE2 baseline instead of auto-detecting AVX2 on the build host so the
# resulting binary runs on older or more constrained CPUs.
RUN git init /tmp/john \
    && cd /tmp/john \
    && git remote add origin https://github.com/openwall/john.git \
    && git fetch --depth 1 origin "${JOHN_REF}" \
    && git checkout --detach FETCH_HEAD \
    && cd /tmp/john/src \
    && ./configure --without-openssl --disable-opencl --disable-pcap --enable-simd=sse2 \
    && make -s clean \
    && make -s -j"$(nproc)" \
    && mkdir -p /opt/john \
    && cp -a /tmp/john/run /opt/john/run \
    && printf '%s\n' '#!/bin/sh' 'exec /opt/john/run/john "$@"' > /opt/john/john-wrapper \
    && chmod +x /opt/john/john-wrapper \
    && /opt/john/run/john --list=formats 2>/dev/null | grep -q "SIP" \
    && rm -rf /tmp/john

FROM python:3.11-slim AS sqlmap-builder

ENV DEBIAN_FRONTEND=noninteractive
ARG SQLMAP_REF=39b8ff4bec7c739973060835c3adaf7bac7447e4

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

RUN git init /tmp/sqlmap \
    && cd /tmp/sqlmap \
    && git remote add origin https://github.com/sqlmapproject/sqlmap.git \
    && git fetch --depth 1 origin "${SQLMAP_REF}" \
    && git checkout --detach FETCH_HEAD \
    && mkdir -p /opt \
    && mv /tmp/sqlmap /opt/sqlmap \
    && rm -rf /opt/sqlmap/.git

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ARG SIPVICIOUS_VERSION=0.3.7
ARG SCAPY_VERSION=2.7.0
ARG WEBSOCKETS_VERSION=16.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        nmap \
        netcat-openbsd \
        inetutils-telnet \
        tcpdump \
        tshark \
        hping3 \
        iperf3 \
        sox \
        sipcrack \
        hashcat \
        sipsak \
        curl \
        wget \
        gnupg \
    && rm -rf /var/lib/apt/lists/*

# Add Kamailio repository for kamcmd (BINRPC client) and install baresip
RUN wget -qO- https://deb.kamailio.org/kamailiodebkey.gpg | gpg --dearmor -o /usr/share/keyrings/kamailio.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/kamailio.gpg] http://deb.kamailio.org/kamailio61 bookworm main" > /etc/apt/sources.list.d/kamailio.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends kamailio baresip-core \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    "sipvicious==${SIPVICIOUS_VERSION}" \
    "scapy==${SCAPY_VERSION}" \
    "websockets==${WEBSOCKETS_VERSION}"

COPY --from=john-builder /opt/john/run /opt/john/run
COPY --from=john-builder /opt/john/john-wrapper /usr/local/bin/john
COPY --from=sqlmap-builder /opt/sqlmap /opt/sqlmap

WORKDIR /opt/testing

COPY scripts/ /opt/testing/scripts/
COPY run-all.sh /usr/local/bin/testing-run-all
COPY attacker-run-all.sh /usr/local/bin/attacker-run-all
COPY smoke.sh /usr/local/bin/testing-smoke

RUN chmod +x /usr/local/bin/testing-run-all /usr/local/bin/attacker-run-all /usr/local/bin/testing-smoke /opt/testing/scripts/*.py \
    && printf '%s\n' '#!/bin/sh' 'exec python3 /opt/sqlmap/sqlmap.py "$@"' > /usr/local/bin/sqlmap \
    && chmod +x /usr/local/bin/sqlmap \
    && ln -sf /opt/testing/scripts/rtpbleed.py /usr/local/bin/rtpbleed \
    && ln -sf /opt/testing/scripts/rtpflood.py /usr/local/bin/rtpflood \
    && ln -sf /opt/testing/scripts/dvrtc-checks.py /usr/local/bin/dvrtc-checks \
    && ln -sf /opt/testing/scripts/turn-probe.py /usr/local/bin/turn-probe \
    && ln -sf /opt/testing/scripts/digestleak.py /usr/local/bin/digestleak \
    && ln -sf /opt/testing/scripts/sqli.py /usr/local/bin/sqli \
    && ln -sf /opt/testing/scripts/freeswitch-lua-sqli.py /usr/local/bin/freeswitch-lua-sqli \
    && ln -sf /opt/testing/scripts/sip-sqlmap-harness.py /usr/local/bin/sip-sqlmap-harness \
    && ln -sf /opt/testing/scripts/xss.py /usr/local/bin/xss

RUN john --list=formats 2>/dev/null | grep -q "SIP" \
    && command -v sipvicious_svwar \
    && command -v sipvicious_svcrack \
    && command -v sipcrack \
    && command -v hashcat \
    && command -v sipsak \
    && command -v tcpdump \
    && command -v tshark \
    && command -v hping3 \
    && command -v iperf3 \
    && command -v sox \
    && command -v curl \
    && command -v sqlmap \
    && command -v attacker-run-all \
    && command -v rtpbleed \
    && command -v rtpflood \
    && command -v dvrtc-checks \
    && command -v turn-probe \
    && command -v digestleak \
    && command -v sqli \
    && command -v freeswitch-lua-sqli \
    && command -v sip-sqlmap-harness \
    && command -v xss \
    && command -v kamcmd \
    && command -v baresip \
    && python3 -c "import scapy" \
    && python3 -c "import websockets" \
    && sqlmap --version

ARG DVRTC_VERSION=dev
ARG DVRTC_SERVICE=testing
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

CMD ["sh"]
