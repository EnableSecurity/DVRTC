# pbx1 Scenario Overview

`pbx1` is the Kamailio/Asterisk/rtpengine scenario in DVRTC. It models a provider-style SIP deployment with a front-end proxy, back-end PBX, separate media relay, exposed web surface, and intentionally weak support services.

This scenario is designed for training and assessment practice across SIP signaling, RTP/media handling, TURN abuse, and SIP-adjacent web/database flaws.

---

Start it with:

```bash
./scripts/compose.sh --scenario pbx1 up -d
```

Equivalent raw Compose command:

```bash
docker compose --project-directory . -p dvrtc-pbx1 -f compose/base.yml -f compose/pbx1.yml up -d
```

---

## Stack

The `pbx1` scenario includes:

- **Kamailio**: SIP proxy/registrar with enumeration and digest-leak-oriented behavior
- **Asterisk**: PBX with weak authentication and vulnerable extensions
- **rtpengine**: media relay configured for RTP bleed and injection exercises
- **coturn**: TURN/STUN server with weak credentials and permissive relay behavior
- **Nginx**: web server exposing voicemail data and collected user-agent logs
- **MySQL**: backing store for SIP user-agent tracking and injection exercises

---

## Training Focus

`pbx1` currently implements training and assessment paths around:

1. **SIP extension enumeration**
2. **VoIP eavesdropping (plaintext SIP/RTP)**
3. **SIP digest authentication leak**
4. **Weak SIP credentials**
5. **RTP bleed**
6. **RTP injection**
7. **RTP flood**
8. **SIP-to-SQL injection**
9. **SIP-to-XSS**
10. **TURN relay abuse**
11. **SIP flood**
12. **Offline credential cracking**

Step-by-step exercise docs currently cover 8 of these paths. The remaining implemented behaviors are described in the component reference docs and can be validated with the `testing` tooling.

The bundled exercises use the tools shipped in the `testing` image, but `pbx1` is a standard SIP/RTP/TURN deployment. Any external VoIP security tool works against it. See [awesome-rtc-hacking](https://github.com/EnableSecurity/awesome-rtc-hacking/?tab=readme-ov-file#open-source-tools) for a curated list.

---

## Default Credentials And Access

### Registerable Accounts

| Extension | Password | Purpose |
|-----------|----------|---------|
| 1000 | 1500 | Weak authentication demo (online cracking) |

Internal caller accounts:

- `sipcaller1` uses a password generated into `.env`

Service targets and special paths:

- `1100` is voicemail and the RTP flood target
- `1200` is the echo service used for RTP injection
- `1300` is the call target used for RTP bleed
- `2000` is the digest-leak target kept registered by the helper service

### Database Access

- MySQL port: `23306` by default, configurable through `MYSQL_PORT`
- Database: `useragents`
- Username: `kamailio`
- Password: `kamailiorw`
- Root password: generated into `.env`

### coturn

- Username: `user`
- Password: `joshua`
- CLI password: `coturn`

### Web Access

- HTTP: `http://your-server-ip`
- HTTPS: `https://your-server-ip`
- WebRTC softphone: `https://your-server-ip/call/`
- User-agent logs: `http://your-server-ip/logs/` with JSON data under `/logs/useragents/`
- Voicemail directory: `http://your-server-ip/voicemail/`
- Secret page: `http://your-server-ip/secret/`
- If `PUBLIC_IPV6` is set, use bracketed URLs such as `http://[your-ipv6]/`

---

## Public Deployment

A live deployment of the `pbx1` scenario is available at `pbx1.dvrtc.net`. People are welcome to test against it.

Use these public endpoints for the shared deployment:

- SIP: `pbx1.dvrtc.net:5060` over UDP or TCP
- SIP/TLS: `pbx1.dvrtc.net:5061`
- SIP over WebSocket: `ws://pbx1.dvrtc.net:8000`
- SIP over Secure WebSocket: `wss://pbx1.dvrtc.net:8443`
- HTTP: `http://pbx1.dvrtc.net/`
- HTTPS: `https://pbx1.dvrtc.net/`
- WebRTC softphone: `https://pbx1.dvrtc.net/call/`
- User-agent logs: `http://pbx1.dvrtc.net/logs/` with JSON data under `/logs/useragents/`
- Voicemail directory: `http://pbx1.dvrtc.net/voicemail/`
- Secret page: `http://pbx1.dvrtc.net/secret/`
- TURN/STUN: `pbx1.dvrtc.net:3478` and `pbx1.dvrtc.net:5349` for TLS

When an exercise or verification command tells you to use `PUBLIC_IPV4` or `your-server-ip`, you can use `pbx1.dvrtc.net` instead when targeting the public deployment.

---

## Exposed Ports

| Port(s) | Protocol | Service | Purpose |
|---------|----------|---------|---------|
| 5060 | UDP/TCP | Kamailio | SIP signaling |
| 5061 | TCP | Kamailio | SIP over TLS |
| 8000 | TCP | Kamailio | WebSocket (WS) |
| 8443 | TCP | Kamailio | WebSocket Secure (WSS) |
| 10000-15000 | UDP | Asterisk | RTP media |
| 35000-40000 | UDP | rtpengine | RTP media proxy |
| 23306 | TCP | MySQL | Exposed database port by default |
| 80 | TCP | Nginx | HTTP web interface |
| 443 | TCP | Nginx | HTTPS web interface |
| 3478 | UDP/TCP | coturn | TURN/STUN |
| 5349 | TCP | coturn | TURN/TLS |

When `PUBLIC_IPV6` is set, Kamailio, coturn, the web surface, and rtpengine-facing media are also exposed over IPv6.

---

## Supporting Docs

- **[Architecture](architecture.md)**: detailed system design, network flow, and vulnerability implementation
- **[Kamailio Configuration](kamailio.md)**: routing logic, custom headers, and SIP behavior
- **[Asterisk Configuration](asterisk.md)**: PBX endpoints, dialplan, media ranges, and voicemail behavior
- **[RTPEngine Reference](rtpengine.md)**: media proxy behavior, port ranges, and control-plane wiring
- **[coturn Reference](coturn.md)**: TURN/STUN behavior, relay policy, and abuse-oriented settings
- **[Nginx Reference](nginx.md)**: exposed web paths, TLS material, and intentionally weak web surface
- **[MySQL Reference](mysql.md)**: exposed database role, schema use, and helper-service integration
- **[Support Services](support-services.md)**: call generators, digest-leak helper, cleaners, and testing containers
- **[Exercise Index](exercises/README.md)**: current hands-on scenario walkthroughs

---

## Notes

- Only one DVRTC scenario runs at a time.
- `pbx1` is selected explicitly with `./scripts/compose.sh --scenario pbx1 up -d`.
