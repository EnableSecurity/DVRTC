# pbx2 Exercise Index

These are the step-by-step hands-on exercises currently documented for the active `pbx2` scenario.

Use the scenario docs and `./scripts/testing-run-all.sh --scenario pbx2` as the source of truth when you need to confirm the current repo behavior.

When an exercise opens a `testing` or `attacker` shell and tells you to use `/work`, that path maps to the repository's `artifacts/` directory. Files you save there remain available on the host after the container exits.

| # | Exercise | Topic |
|---|----------|-------|
| 1 | [INVITE-Based SIP Enumeration](01-invite-enumeration.md) | Classify routable, known-but-unregistered, and invalid extensions from unauthenticated `INVITE` responses |
| 2 | [Traffic Analysis & Packet Capture](02-traffic-analysis.md) | Capture plaintext SIP and RTP from the default background call flow |
| 3 | [Online SIP Credential Cracking](03-online-credential-cracking.md) | Brute-force the weak password on extension `1000` |
| 4 | [SIP Digest Leak](04-digest-leak.md) | Exploit extension `2000` to capture digest material |
| 5 | [Offline SIP Credential Cracking](05-offline-credential-cracking.md) | Crack the leaked SIP digest offline with `john` |
| 6 | [RTP Bleed Attack](06-rtp-bleed.md) | Probe the exposed RTP range and recover leaked media packets |
| 7 | [RTP Flood / Recording Growth](07-rtp-flood.md) | Inflate recording size by flooding the media target during a call |
| 8 | [SIP Flood](08-sip-flood.md) | Send repeated unauthenticated SIP requests and confirm the edge does not throttle them |
| 9 | [FreeSWITCH Lua SQL Injection](09-freeswitch-lua-sqli.md) | Use a malicious called SIP URI to query the route for the hidden internal-only `9000` HAL path through an unsafe Lua `freeswitch.Dbh` query on `2001` |
| 10 | [Automated FreeSWITCH Lua SQLite Exfiltration with sqlmap](10-sqli-automation.md) | Use `sip-sqlmap-harness` and `sqlmap` to fingerprint SQLite and dump `did_routes` through the Lua `freeswitch.Dbh` SQL injection |

## Related Documentation

- [pbx2 Scenario Overview](../overview.md)
- [pbx2 Architecture](../architecture.md)
- [Troubleshooting](../../troubleshooting.md)
