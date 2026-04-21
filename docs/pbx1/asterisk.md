# Asterisk Configuration Reference

## Role In Scenario

Asterisk is the `pbx1` back-end PBX. Kamailio forwards SIP signaling to it over loopback TCP, while media is handled through the host network and coordinated with `rtpengine`.

- terminates the authenticated user endpoint `1000`
- provides voicemail at `1100`
- provides an echo service at `1200` and a call-generator target at `1300` (used for RTP bleed demos)
- writes voicemail into the shared volume later exposed by Nginx
- extension `2000` is not an Asterisk endpoint; Kamailio handles it as a helper-backed digest-leak target

## Key Files

| File | Purpose |
|------|---------|
| `build/asterisk/config/pjsip.conf` | endpoint, auth, and transport definitions |
| `build/asterisk/config/extensions.conf` | dialplan logic for `1000`, `1100`, `1200`, and `1300` |
| `build/asterisk/config/voicemail.conf` | voicemail behavior and mailbox definitions |
| `build/asterisk/config/rtp.conf` | RTP port range and media behavior |
| `build/asterisk/config/manager.conf` | AMI access and related controls |
| `build/asterisk/run.sh` | runtime setup and config templating |

## Intentionally Vulnerable Behavior

- `1000` uses intentionally weak credentials (`1500`)
- voicemail files are shared into a web-exposed path
- SRTP is not enforced
- RTP handling is permissive enough for injection, bleed, and flood exercises
- `1100`, `1200`, and `1300` are dialplan targets, not separate authenticated PJSIP endpoints

## Verification

Use the `testing` profile for repeatable checks:

```bash
./scripts/compose.sh --scenario pbx1 run --rm testing dvrtc-checks register --host 127.0.0.1
./scripts/compose.sh --scenario pbx1 run --rm testing dvrtc-checks bad-auth --host 127.0.0.1
./scripts/compose.sh --scenario pbx1 run --rm testing dvrtc-checks voicemail --host 127.0.0.1
./scripts/compose.sh --scenario pbx1 logs asterisk
```

## Related Documentation

- [Overview](overview.md)
- [Architecture](architecture.md)
- [Kamailio Configuration](kamailio.md)
- [Support Services](support-services.md)
