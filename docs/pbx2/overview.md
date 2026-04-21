# pbx2 Scenario Overview

`pbx2` is the OpenSIPS/FreeSWITCH/rtpproxy scenario in DVRTC. It is a focused SIP/RTP training stack with an OpenSIPS edge, a FreeSWITCH back-end PBX, and rtpproxy as a recording media relay.

This scenario is designed for training and assessment practice across SIP signaling, FreeSWITCH/Lua SQL injection, digest authentication leakage, weak credentials, RTP/media abuse, recorded packet captures, and SIP flood behavior.

Start it with:

```bash
./scripts/compose.sh --scenario pbx2 up -d
```

Equivalent raw Compose command:

```bash
docker compose --project-directory . -p dvrtc-pbx2 -f compose/base.yml -f compose/pbx2.yml up -d
```

## Stack

The `pbx2` scenario includes:

- **OpenSIPS**: SIP proxy/registrar with INVITE-based extension classification, the digest-leak call path, and no active SIP throttling
- **FreeSWITCH**: PBX with weak endpoint credentials and distinct downstream call outcomes that feed the enumeration path
- **rtpproxy**: media relay with public RTP exposure and unconditional packet capture
- **Nginx**: web server exposing the scenario landing page and the RTP recordings directory

## Training Focus

`pbx2` currently implements training and assessment paths around:

1. **INVITE-based SIP enumeration**
2. **FreeSWITCH Lua SQL injection**
3. **Plaintext SIP/RTP traffic analysis**
4. **Weak SIP credentials / online credential cracking**
5. **SIP digest authentication leak**
6. **Offline credential cracking**
7. **RTP bleed**
8. **RTP flood / recording storage abuse**
9. **SIP flood**

The exercise index covers each current path. The bundled regression checks remain the source of truth for reproducibility.

See [Exercise Index](exercises/README.md) for the current pbx2 walkthroughs.

## Default Credentials And Access

### Registerable Accounts

| Extension | Password | Purpose |
|-----------|----------|---------|
| 1000 | 1500 | Weak authentication demo and online cracking target |

Internal caller accounts:

- `sipcaller1` uses a password generated into `.env`

Service targets and special paths:

- `1200` is the echo service and the RTP flood target
- `1300` is the background call target used for RTP bleed and traffic-analysis exercises
- `2001` is the public front-door service for the FreeSWITCH Lua SQL injection demo and plays the HAL-style public path
- `9000` is a hidden internal-only maintenance-style service that the Lua SQL injection can unlock by querying its route from the same database
- `2000` is the digest-leak target; it is anonymously callable, but only the loopback helper is allowed to register it

### Web Access

- HTTP: `http://your-server-ip`
- HTTPS: `https://your-server-ip`
- RTP recordings directory: `http://your-server-ip/recordings/`
- Active recording spool: `http://your-server-ip/recordings/spool/`
- If `PUBLIC_IPV6` is set, use bracketed URLs such as `http://[your-ipv6]/recordings/`

## Public Deployment

A live deployment of the `pbx2` scenario is available at `pbx2.dvrtc.net`. People are welcome to test against it.

Use these public endpoints for the shared deployment:

- SIP: `pbx2.dvrtc.net:5060` over UDP or TCP
- SIP/TLS: `pbx2.dvrtc.net:5061`
- HTTP: `http://pbx2.dvrtc.net/`
- HTTPS: `https://pbx2.dvrtc.net/`
- RTP recordings directory: `http://pbx2.dvrtc.net/recordings/`
- Active recording spool: `http://pbx2.dvrtc.net/recordings/spool/`

When an exercise or verification command tells you to use `PUBLIC_IPV4` or `your-server-ip`, you can use `pbx2.dvrtc.net` instead when targeting the public deployment.

---

## Exposed Ports

| Port(s) | Protocol | Service | Purpose |
|---------|----------|---------|---------|
| 5060 | UDP/TCP | OpenSIPS | SIP signaling |
| 5061 | TCP | OpenSIPS | SIP over TLS |
| 35000-40000 | UDP | rtpproxy | RTP media proxy |
| 80 | TCP | Nginx | HTTP web interface |
| 443 | TCP | Nginx | HTTPS web interface |

## Verify The Scenario

```bash
./scripts/testing-smoke.sh --scenario pbx2
./scripts/testing-run-all.sh --scenario pbx2
./scripts/attacker-run-all.sh --scenario pbx2
```

## Supporting Docs

- **[Architecture](architecture.md)**: system design, network flow, and deliberately vulnerable behavior
- **[OpenSIPS Configuration](opensips.md)**: routing logic, transport exposure, and digest-leak-specific handling
- **[FreeSWITCH Configuration](freeswitch.md)**: PBX users, dialplan targets, and registration behavior
- **[RTPProxy Reference](rtpproxy.md)**: media anchoring, recording behavior, and RTP-specific exercise surfaces
- **[Nginx Reference](nginx.md)**: exposed web paths, recordings web surface, and version endpoint
- **[Support Services](support-services.md)**: call generators, digest-leak helper, cleaner, and test runners
- **[Exercise Index](exercises/README.md)**: current pbx2 hands-on exercises
- **[Troubleshooting](../troubleshooting.md)**: current repo-specific failure modes and diagnostics
