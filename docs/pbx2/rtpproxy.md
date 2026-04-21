# RTPProxy Reference

## Role In Scenario

`rtpproxy` is the media relay for the `pbx2` scenario. OpenSIPS controls it over the local control socket, and the service exposes a large public RTP range on the host.

The current setup is intentionally permissive and records every anchored session so the lab can demonstrate RTP bleed and flooding behavior while keeping captured media available through the scenario web surface.

- OpenSIPS controls `rtpproxy` on `127.0.0.1:7722/UDP`
- public RTP range is `35000-40000/UDP`
- advertised media address comes from `PUBLIC_IPV4`
- active recordings are written under `/recordings/spool`
- completed packet captures are written under `/recordings` in `.pcap` format
- `pbx2` currently anchors media on IPv4 only

## Key Files

| File | Purpose |
|------|---------|
| `build/rtpproxy/run.sh` | launches `rtpproxy` with the DVRTC port range and recording options |
| `build/rtpproxy/healthcheck/healthcheck.sh` | service health validation |
| `build/opensips/config/opensips.cfg` | `rtpproxy` control calls during offer/answer handling |
| `compose/pbx2.yml` | runtime wiring, recording volume, and host-network setup |

## Intentionally Vulnerable Behavior

- every anchored session is recorded unconditionally with `-a`
- the public RTP range is large and predictable enough for probing exercises
- arbitrary RTP toward active media targets can grow recordings rapidly during flood exercises
- the training setup remains permissive enough for RTP bleed-style probing

## Verification

```bash
./scripts/compose.sh --scenario pbx2 run --rm testing dvrtc-checks rtp-bleed --host 127.0.0.1
./scripts/testing-run-all.sh --scenario pbx2
./scripts/compose.sh --scenario pbx2 logs rtpproxy
```

## Related Documentation

- [Overview](overview.md)
- [Architecture](architecture.md)
- [OpenSIPS Configuration](opensips.md)
- [Nginx Reference](nginx.md)
