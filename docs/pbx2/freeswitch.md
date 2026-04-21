# FreeSWITCH Configuration Reference

## Role In Scenario

FreeSWITCH is the `pbx2` back-end PBX. OpenSIPS forwards SIP signaling to it over loopback UDP, while public media is anchored through `rtpproxy`.

- listens for SIP from OpenSIPS on `127.0.0.1:5090/UDP`
- uses RTP ports `10000-15000/UDP` on the local host side
- terminates authenticated user endpoints `1000` and `sipcaller1`
- provides the echo targets at `1200` and `1300`, plus the HAL-style services at `2001` and `9000`
- drives the downstream call outcomes that OpenSIPS leaks during INVITE-based enumeration

## Key Files

| File | Purpose |
|------|---------|
| `build/freeswitch/config/directory/default.xml` | user directory, passwords, and caller identity |
| `build/freeswitch/config/dialplan/default.xml` | dialplan for `1000`, `1200`, `1300`, `2001`, `9000`, and invalid numbers |
| `build/freeswitch/config/sip_profiles/internal.xml` | SIP bind, RTP range, and registration settings |
| `build/freeswitch/config/autoload_configs/modules.conf.xml` | enabled FreeSWITCH modules |
| `build/freeswitch/config/autoload_configs/lua.conf.xml` | Lua script directory configuration |
| `build/freeswitch/scripts/map_did_to_route.lua` | intentionally vulnerable `freeswitch.Dbh` routing demo |
| `build/freeswitch/run.sh` | runtime password templating, DID-route DB seeding, and startup |

## Intentionally Vulnerable Behavior

- extension `1000` uses the intentionally weak password `1500`
- extension `2001` runs an intentionally vulnerable Lua `freeswitch.Dbh` query that concatenates the called SIP URI user part into SQL; normal calls to `2001` resolve to the public `2001/public` route target, while an injected called URI such as `2001'/**/AND/**/0/**/UNION/**/SELECT/**/target,scope/**/FROM/**/did_routes/**/WHERE/**/did='9000` can query the routing table for the hidden `9000/internal` target and reroute the call there
- the `did_routes` SQLite table is seeded at FreeSWITCH startup, while the Lua lookup path itself performs only the vulnerable `SELECT`
- `1300` answers silently and stays active, which helps keep RTP flowing for traffic-analysis and bleed exercises
- the catch-all invalid dialplan path makes bad destinations behave differently from valid-but-unregistered targets, which supports enumeration through the OpenSIPS front end
- codec negotiation is intentionally permissive enough to keep the lab easy to interoperate with during testing

## Scenario-Specific Notes

### Endpoint And Dialplan Split

- `1000` and `sipcaller1` are authenticated directory users
- `2000` is not present in the FreeSWITCH directory; OpenSIPS handles it locally for the digest-leak path
- `1200`, `1300`, `2001`, and `9000` are dialplan services, not separate authenticated SIP endpoints
- `1200` is the echo target used by manual checks and RTP flood exercises
- `1300` is the call-generator target used for RTP bleed and traffic-analysis exercises
- `2001` is the public front-door service for the FreeSWITCH/Lua/SQLite SQL injection demo and plays a HAL introduction followed by a refusal quote
- `9000` is a hidden internal-only maintenance-style service that is intended to be reachable only through the vulnerable Lua DID lookup and plays the access-granted clip when the SQL injection reaches it

### Registration Model

FreeSWITCH does not listen publicly in this scenario. OpenSIPS forwards normal `REGISTER` requests to `127.0.0.1:5090/UDP`, while extension `2000` is handled entirely as an OpenSIPS-local registration and INVITE path instead of a FreeSWITCH registration path.

## Verification

```bash
./scripts/compose.sh --scenario pbx2 run --rm testing dvrtc-checks register --host 127.0.0.1 --username 1000 --password 1500
./scripts/compose.sh --scenario pbx2 run --rm testing dvrtc-checks digestleak-auth --host 127.0.0.1
./scripts/compose.sh --scenario pbx2 run --rm testing dvrtc-checks bad-auth --host 127.0.0.1 --username 1000
./scripts/compose.sh --scenario pbx2 run --rm testing freeswitch-lua-sqli --host 127.0.0.1 --extension 2001
./scripts/compose.sh --scenario pbx2 logs freeswitch
```

## Related Documentation

- [Overview](overview.md)
- [Architecture](architecture.md)
- [OpenSIPS Configuration](opensips.md)
- [Support Services](support-services.md)
