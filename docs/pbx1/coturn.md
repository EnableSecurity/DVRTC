# coturn Reference

## Role In Scenario

`coturn` provides TURN/STUN support for the `pbx1` scenario. It is intentionally configured with weak credentials and a relay policy that denies all peers by default then allows back loopback, RFC 1918 ranges, and the host's own public IP, so the lab can demonstrate TURN relay abuse.

- public listeners: `3478/TCP`, `3478/UDP`, and `5349/TCP` for TURN/TLS
- network mode: host
- TLS material is read from `data/certs`
- listeners are created for `127.0.0.1`, `PUBLIC_IPV4`, and optional `PUBLIC_IPV6`

## Key Files

| File | Purpose |
|------|---------|
| `compose/pbx1.yml` | `coturn` command, listener policy, and health check |
| `data/certs/` | certificate material for TURN/TLS use cases |
| `docs/pbx1/exercises/06-turn-relay-abuse.md` | current hands-on abuse exercise |

## Intentionally Vulnerable Behavior

- TURN user: `user`
- TURN password: `joshua`
- CLI password: `coturn`
- realm is `dvrtc.local`
- loopback peers are allowed
- private-network peers are allowed
- the host's public IPs are also allowed relay targets

Alongside the intentional vulnerabilities, coturn runs with several operational hardening flags: `--response-origin-only-with-rfc5780`, `--no-software-attribute`, and `--no-rfc5780`.

## Verification

```bash
. ./.env
./scripts/compose.sh --scenario pbx1 run --rm attacker turn-probe tcp-http-get --host "$PUBLIC_IPV4" --username user --password joshua --peer 127.0.0.1 --path /secret/
./scripts/compose.sh --scenario pbx1 run --rm attacker turn-probe tcp-http-get --tls --port 5349 --host "$PUBLIC_IPV4" --username user --password joshua --peer 127.0.0.1 --path /secret/
./scripts/compose.sh --scenario pbx1 logs coturn
```

## Related Documentation

- [Overview](overview.md)
- [Architecture](architecture.md)
- [TURN Relay Abuse Exercise](exercises/06-turn-relay-abuse.md)
- [Troubleshooting](../troubleshooting.md)
