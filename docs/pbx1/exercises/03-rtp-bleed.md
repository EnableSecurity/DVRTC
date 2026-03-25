# Exercise 3: RTP Bleed with the DVRTC rtp-bleed Check

## Goal

Use the `dvrtc-checks.py rtp-bleed` wrapper in the `attacker` service to probe DVRTC's external RTP range and confirm that RTP packets can be received without being part of the call. The lab already has multiple background call-generator calls in progress, and this exercise aims to bleed one or more of those streams.

## Prerequisites

- DVRTC running: `docker compose up -d`
- the `dvrtc-checks.py rtp-bleed` helper available in the `attacker` service

## Steps

### Step 1: Read the advertised IPv4 from `.env`

Run on the host:

```bash
. ./.env
```

### Step 2: Probe the RTP range

Run on the host:

```bash
docker compose run --rm attacker python3 /opt/testing/scripts/dvrtc-checks.py rtp-bleed --host "$PUBLIC_IPV4"
```

This targets the lab's external RTP path and sends the probes from the bridge-networked attacker container.

### Step 3: Observe the leaked RTP response

Look for output like:

```text
[*] RTP bleed check: probing 192.0.2.10:35000-40000
    [*] Attempt 1/3
[+] RTP response from 192.0.2.10:36608 (172 bytes)
[+] RTP bleed vulnerability confirmed via 192.0.2.10
```

The exact IP and port will vary, but a positive RTP response confirms that media is being exposed on the external RTP path.

### Step 4: Verify

If the command reports an RTP response and prints `RTP bleed vulnerability confirmed`, the exercise succeeded. You can optionally inspect the leaked traffic with the packet-capture workflow from Exercise 2.

## What's happening

DVRTC continuously generates multiple background calls, so RTP is already flowing through the exposed media ranges before you do anything. The RTP bleed helper sprays RTP probes across the configured external RTP range and listens for returned RTP packets, with the goal of bleeding one or more of those active call-generator streams.

This works because the default `rtpengine` behavior accepts media from probed RTP ports unless stricter source validation is enabled. An attacker can discover an active RTP port and receive media even though they are not a legitimate call participant.

## Mitigation

- Enable `strict source` in `rtpengine` so packets from unexpected source IPs or ports are dropped instead of forwarded after endpoint learning
- Where your deployment does not need RTP source learning, set `endpoint-learning=off`; this is often a good fit when clients use STUN correctly or are not behind NAT
- If source learning is still required for NATed clients, prefer `endpoint-learning=heuristic` instead of more permissive learning behavior
- Use SRTP to protect media confidentiality, but note that RTP bleed may still work as a denial-of-service vector even when the leaked media is encrypted
- Limit RTP exposure to trusted networks and expected peers
