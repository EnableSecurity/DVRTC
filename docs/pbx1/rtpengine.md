# RTPEngine Reference

## Role In Scenario

`rtpengine` is the media relay for the `pbx1` scenario. Kamailio controls it over the NG control socket, and the service exposes public RTP ports on the host for realistic media handling.

The current setup is intentionally permissive to support RTP bleed, injection, and related training exercises.

- Kamailio controls `rtpengine` via the NG protocol over UDP on `127.0.0.1:2223`
- RTP range is `35000-40000/UDP`
- advertised addresses come from `PUBLIC_IPV4` and optional `PUBLIC_IPV6`
- it sits between client media and Asterisk's `10000-15000/UDP` RTP range
- the active `1300` call target is kept busy by the call generators so bleed checks have traffic to observe
- Kamailio's `NATMANAGE` route passes `ICE=remove` and `rtcp-mux-demux` flags for client-side offers, stripping ICE candidates and splitting RTCP back onto a separate port for Asterisk

## Key Files

| File | Purpose |
|------|---------|
| `build/rtpengine/run.sh` | launches `rtpengine` with the DVRTC port range and interfaces |
| `build/rtpengine/healthcheck/healthcheck.sh` | service health validation |
| `build/kamailio/config/kamailio.cfg` | `rtpengine` control commands and SDP handling |
| `docker-compose.yml` | runtime wiring, health check, and host-network setup |

## Intentionally Vulnerable Behavior

- rtpengine runs with default source-learning behavior and no strict source enforcement, enabling RTP bleed demonstrations
- arbitrary-source RTP injection remains possible in the training setup
- port behavior is predictable enough for probing exercises

## Verification

```bash
docker compose run --rm testing python3 /opt/testing/scripts/dvrtc-checks.py rtp-bleed --host 127.0.0.1
docker compose logs rtpengine
```

## Related Documentation

- [Overview](overview.md)
- [Architecture](architecture.md)
- [Kamailio Configuration](kamailio.md)
- [Asterisk Configuration](asterisk.md)
