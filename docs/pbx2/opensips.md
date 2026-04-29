# OpenSIPS Configuration Reference

## Role In Scenario

OpenSIPS is the public SIP edge for `pbx2`. It accepts SIP over UDP, TCP, and TLS, proxies most signaling to FreeSWITCH, controls `rtpproxy`, and owns the scenario's INVITE-based enumeration and digest-leak-specific routing behavior.

- public SIP on `5060/UDP` and `5060/TCP`
- SIP/TLS on `5061/TCP` when certificate material exists under `data/certs`
- `rtpproxy` control via UDP on `127.0.0.1:7722`
- forwarding of normal registrations and calls to FreeSWITCH on `127.0.0.1:5090/UDP`
- a dedicated loopback-only registration path for extension `2000`
- shared memory set by `OPENSIPS_SHM_MB`, defaulting to `128` MB
- no WS or WSS browser signaling path in this scenario

## Key Files

| File | Purpose |
|------|---------|
| `build/opensips/config/opensips.cfg` | main routing logic and intentional vulnerabilities |
| `build/opensips/config/tls.cfg` | TLS settings for SIP/TLS |
| `build/opensips/run.sh` | runtime listen-address generation for IPv4 and optional IPv6 |
| `compose/pbx2.yml` | service wiring, health check, and environment |

## Intentionally Vulnerable Behavior

- unauthenticated `INVITE` requests return different SIP responses for valid, valid-but-unregistered, and invalid targets, which enables the `pbx2` enumeration path
- extension `2000` is special-cased for the digest-leak exercise and routed through usrloc-backed helper registration instead of the normal FreeSWITCH path
- extension `2000` only accepts `REGISTER` from loopback, so the local helper can keep it online while public clients cannot register it directly
- there is no active SIP request throttling in the OpenSIPS routing logic, which supports SIP flood exercises
- `verify_cert` and `require_cert` are disabled for the default TLS domain in the current lab setup

## Scenario-Specific Notes

### Enumeration Behavior

- `1200` is the routable echo target used by the `invite-enum` check
- `1000` is a known user path that is intentionally left unregistered by default
- `9999` falls through the invalid-extension path
- the regression suite treats those three outcomes as `routable`, `known-unregistered`, and `invalid`

### Transport Exposure

`build/opensips/run.sh` builds listeners from `PUBLIC_IPV4`, optional `PUBLIC_IPV6`, and loopback. This means the proxy stays reachable on `127.0.0.1:5060` for local service traffic even when the public bind address is a specific host IP.

### Shared Memory

`OPENSIPS_SHM_MB` defaults to `128` MB. This keeps flood exercises from immediately exhausting transaction shared memory while preserving the intentionally vulnerable lack of SIP request throttling.

## Verification

```bash
./scripts/compose.sh --scenario pbx2 run --rm testing dvrtc-checks invite-enum --host 127.0.0.1 --extensions 1200,1000,9999 --expect 1200=routable --expect 1000=known-unregistered --expect 9999=invalid
./scripts/compose.sh --scenario pbx2 run --rm testing dvrtc-checks digestleak-auth --host 127.0.0.1
./scripts/compose.sh --scenario pbx2 run --rm testing dvrtc-checks sip-transport --scenario pbx2 --host 127.0.0.1
./scripts/compose.sh --scenario pbx2 logs opensips
```

## Related Documentation

- [Overview](overview.md)
- [Architecture](architecture.md)
- [FreeSWITCH Configuration](freeswitch.md)
- [RTPProxy Reference](rtpproxy.md)
