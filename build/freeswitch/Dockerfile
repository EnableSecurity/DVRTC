FROM debian:bookworm AS builder

ARG FREESWITCH_VERSION=v1.10.12

RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    libcurl4-openssl-dev \
    libpcre3-dev \
    libspeex-dev \
    libspeexdsp-dev \
    libedit-dev \
    libldns-dev \
    liblua5.2-dev \
    libopus-dev \
    libsndfile1-dev \
    libavformat-dev \
    libswscale-dev \
    libtiff-dev \
    yasm \
    uuid-dev \
    libsqlite3-dev \
    zlib1g-dev \
    cmake \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/local/src

# Build spandsp3 from source (required by FreeSWITCH)
RUN git clone https://github.com/freeswitch/spandsp.git && \
    cd spandsp && \
    ./bootstrap.sh && \
    ./configure --prefix=/usr && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# Build sofia-sip from source (required by FreeSWITCH)
RUN git clone https://github.com/freeswitch/sofia-sip.git && \
    cd sofia-sip && \
    ./bootstrap.sh && \
    ./configure --prefix=/usr && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# Build libks2 from source
RUN git clone https://github.com/signalwire/libks.git && \
    cd libks && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release . && \
    make -j$(nproc) && \
    make install && \
    ldconfig

RUN git clone --depth 1 --branch ${FREESWITCH_VERSION} https://github.com/signalwire/freeswitch.git

WORKDIR /usr/local/src/freeswitch

# Bootstrap and configure
RUN ./bootstrap.sh -j

# Customize modules - enable only what we need and keep the pbx2 image lean.
RUN sed -i 's/#formats\/mod_sndfile/formats\/mod_sndfile/' modules.conf && \
    sed -i 's/#endpoints\/mod_verto/endpoints\/mod_verto/' modules.conf && \
    sed -i 's/#languages\/mod_lua/languages\/mod_lua/' modules.conf && \
    sed -i 's/applications\/mod_signalwire/#applications\/mod_signalwire/' modules.conf && \
    sed -i 's/databases\/mod_pgsql/#databases\/mod_pgsql/' modules.conf && \
    sed -i 's/applications\/mod_spandsp/#applications\/mod_spandsp/' modules.conf

RUN ./configure --prefix=/opt/freeswitch \
    --disable-debug \
    --disable-libyuv \
    --disable-libvpx

RUN make -j$(nproc) && make install

# Install sounds
RUN make sounds-install && make moh-install

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libssl3 \
    libsqlite3-0 \
    libcurl4 \
    libpcre3 \
    libspeex1 \
    libspeexdsp1 \
    libedit2 \
    libldns3 \
    liblua5.2-0 \
    libopus0 \
    libsndfile1 \
    libtiff6 \
    sqlite3 \
    uuid-runtime \
    && rm -rf /var/lib/apt/lists/*

# Copy spandsp, sofia-sip, and libks libraries from builder.
# Debian installs some of these into the multiarch library directory.
COPY --from=builder /usr/lib/x86_64-linux-gnu/libspandsp* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/libsofia* /usr/lib/
COPY --from=builder /usr/lib/libks* /usr/lib/
RUN ldconfig

COPY --from=builder /opt/freeswitch /opt/freeswitch

# Create freeswitch user
RUN useradd -r -u 15003 -d /opt/freeswitch freeswitch && \
    mkdir -p /var/lib/freeswitch/db && \
    mkdir -p /var/log/freeswitch && \
    mkdir -p /var/run/freeswitch && \
    mkdir -p /etc/certstore && \
    chown -R freeswitch:freeswitch /opt/freeswitch /var/lib/freeswitch /var/log/freeswitch /var/run/freeswitch

# Link to standard locations
RUN ln -s /opt/freeswitch/bin/freeswitch /usr/local/bin/freeswitch && \
    ln -s /opt/freeswitch/bin/fs_cli /usr/local/bin/fs_cli

WORKDIR /opt/freeswitch/conf

# Remove default config and add our own
RUN rm -rf /opt/freeswitch/conf/*
COPY config/ /opt/freeswitch/conf/
COPY scripts/ /opt/freeswitch/scripts/
COPY sounds/*.wav /opt/freeswitch/share/freeswitch/sounds/en/us/callie/dvrtc/8000/
COPY sounds/ivr/ /opt/freeswitch/share/freeswitch/sounds/ivr/

RUN chown -R freeswitch:freeswitch /opt/freeswitch/conf /opt/freeswitch/scripts /opt/freeswitch/share/freeswitch/sounds/en/us/callie/dvrtc /opt/freeswitch/share/freeswitch/sounds/ivr

COPY --chmod=755 healthcheck/healthcheck.sh /usr/local/bin/freeswitch-healthcheck
COPY run.sh /opt/run.sh
RUN chmod +x /opt/run.sh && chown freeswitch:freeswitch /opt/run.sh

ARG DVRTC_VERSION=dev
ARG DVRTC_SERVICE=freeswitch
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

USER freeswitch

CMD ["/opt/run.sh"]
