# pbx1 Exercise Index

These are the step-by-step hands-on exercises currently documented for the active `pbx1` scenario.

The scenario implements additional vulnerability paths beyond this list. For those, use the component reference docs and the `testing-run-all` checks as the current source of truth.

When an exercise opens a `testing` or `attacker` shell and tells you to use `/work`, that path maps to the repository's `artifacts/` directory. Files you save there remain available on the host after the container exits.

| # | Exercise | Topic |
|---|----------|-------|
| 1 | [SIP Extension Enumeration](01-enumeration.md) | Discover valid extensions via response code analysis |
| 2 | [Traffic Analysis & Packet Capture](02-traffic-analysis.md) | Capture SIP/RTP traffic and inspect recovered media |
| 3 | [RTP Bleed Attack](03-rtp-bleed.md) | Probe the exposed RTP range and recover leaked media packets |
| 4 | [Online SIP Credential Cracking](04-credential-cracking.md) | Brute-force the weak password on extension `1000` |
| 5 | [SIP Digest Leak](05-digest-leak.md) | Exploit extension `2000` to capture digest material and crack it offline |
| 6 | [TURN Relay Abuse](06-turn-relay-abuse.md) | Abuse coturn relay permissions to reach loopback-only HTTP content |
| 7 | [Offline SIP Credential Cracking](07-offline-credential-cracking.md) | Capture and crack SIP digest material offline |
| 8 | [Automated SIP → MySQL Data Exfiltration with sqlmap](08-sqli-automation.md) | Use `sip-sqlmap-harness` and `sqlmap` to dump the seeded `customers` table through the Kamailio User-Agent SQL injection |

## Related Documentation

- [pbx1 Scenario Overview](../overview.md)
- [pbx1 Architecture](../architecture.md)
- [Troubleshooting](../../troubleshooting.md)
