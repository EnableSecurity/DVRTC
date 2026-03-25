# Kamailio Configuration Reference

## Role In Scenario

Kamailio is the public SIP edge for `pbx1`. It accepts SIP over UDP, TCP, TLS, WS, and WSS, proxies signaling to Asterisk, controls `rtpengine`, and owns several of the lab's intentionally vulnerable behaviors.

- public SIP on `5060/UDP` and `5060/TCP`
- SIP/TLS on `5061/TCP`
- SIP-over-WebSocket on `8000/TCP`
- SIP-over-secure-WebSocket on `8443/TCP`
- `rtpengine` control via the NG protocol over UDP on `127.0.0.1:2223`
- MySQL logging to the `useragents` database
- bootstrap of the `useragents` schema and seeded fake `customers` data in `build/kamailio/run.sh`

## Key Files

| File | Purpose |
|------|---------|
| `build/kamailio/config/kamailio.cfg` | main routing logic and intentional vulnerabilities |
| `build/kamailio/config/tls.cfg` | TLS settings for SIP/TLS and WSS |
| `build/kamailio/run.sh` | runtime templating for public IPs, ports, and aliases |
| `docker-compose.yml` | service wiring, health check, and environment |

## Intentionally Vulnerable Behavior

- `ALLOWED_EXTENSIONS` is used to return `404` for unknown extensions and different responses for valid ones, enabling extension enumeration
- extension `2000` only authenticates `REGISTER`, which supports the digest-leak exercise
- extension `2000` registrations are only accepted from RFC1918 space or loopback
- SIP `User-Agent` headers are inserted into MySQL without sanitization, enabling SQL injection
- the same logged `User-Agent` data is later rendered in the web UI, enabling XSS
- there is no active SIP request throttling in the routing logic, which supports SIP flood exercises

## Scenario-Specific Notes

### Extension Handling

- valid extensions are `sipcaller1`, `2000`, `1000`, `1100`, `1200`, and `1300`
- `2000` is the special digest-leak target
- `1300` is the call-generator target used for RTP bleed exercises

### Dialog Handling For `2000`

Kamailio tracks dialog state for calls to `2000` so in-dialog requests can be routed back to the registered helper and then back to the original caller, which keeps the digest-leak scenario reproducible.

## Verification

```bash
docker compose run --rm testing python3 /opt/testing/scripts/dvrtc-checks.py enum --host 127.0.0.1 --extension 2000
docker compose run --rm testing python3 /opt/testing/scripts/dvrtc-checks.py digestleak-registered --host 127.0.0.1
docker compose run --rm testing python3 /opt/testing/scripts/dvrtc-checks.py sqli --host 127.0.0.1 --extension 1000
docker compose run --rm testing python3 /opt/testing/scripts/dvrtc-checks.py xss --host 127.0.0.1 --extension 1000
docker compose run --rm testing python3 /opt/testing/scripts/dvrtc-checks.py sip-transport --host 127.0.0.1
docker compose logs kamailio
```

## Related Documentation

- [Overview](overview.md)
- [Architecture](architecture.md)
- [Asterisk Configuration](asterisk.md)
- [RTPEngine Reference](rtpengine.md)
- [MySQL Reference](mysql.md)
