# Exercise 1: SIP Extension Enumeration with svwar

## Goal

Use SIPVicious OSS `svwar` to identify valid SIP extensions on DVRTC by comparing how the server responds to known and unknown numbers.

## Prerequisites

- DVRTC running: `docker compose up -d`
- SIPVicious OSS available in the `attacker` service

## Steps

### Step 1: Read the advertised IPv4 from `.env`

Run on the host:

```bash
. ./.env
```

### Step 2: Open an interactive attacker shell

Run on the host:

```bash
docker compose run --rm attacker bash
```

### Step 3: Probe a known extension

In the attacker shell:

```bash
sipvicious_svwar -e 1000 "udp://$PUBLIC_IPV4:5060" -v
```

Look for `1000` to be reported as a valid extension, typically with an authentication-required result.

### Step 4: Enumerate the default lab range

In the attacker shell:

```bash
sipvicious_svwar -e 1000-2000 "udp://$PUBLIC_IPV4:5060" -v
```

Expected hits in the default DVRTC configuration are `1000`, `1100`, `1200`, `1300`, and `2000`.

### Step 5: Check an invalid extension

In the attacker shell:

```bash
sipvicious_svwar -e 9999 "udp://$PUBLIC_IPV4:5060" -v --debug
```

`9999` should not be reported as valid. In the debug output, look for `SIP/2.0 404 enumerate me baby`. Valid targets produce a different response and are reported as existing by `svwar`.

## What's happening

DVRTC is intentionally vulnerable to SIP extension enumeration. Kamailio checks the requested extension against an allow-list and immediately returns `404` for unknown targets. Valid extensions such as `1000`, `1100`, `1200`, `1300`, and `2000` continue into the normal SIP handling path, which produces a different response pattern.

`svwar` automates this by sending SIP probes across a range and classifying the replies. Because the server does not normalize responses, an attacker can quickly build a list of real extensions for follow-on attacks.

## Mitigation

- Return the same generic response for valid and invalid extensions; this is the primary mitigation
- Rate-limit and alert on sequential SIP enumeration attempts
- Expose SIP only through trusted networks, VPNs, or an SBC
- Monitor SIP logs for repeated scans across extension ranges
