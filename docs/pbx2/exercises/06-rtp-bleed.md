# Exercise 6: RTP Bleed Attack

## Goal

Probe the exposed `pbx2` RTP range and confirm that media packets can be received without being part of the call. `pbx2` continuously generates background calls to extension `1300`, so RTP is already flowing through `rtpproxy`, and this exercise aims to bleed one or more of those streams.

## Prerequisites

- DVRTC running: `./scripts/compose.sh --scenario pbx2 up -d`
- `rtpbleed` available in the `attacker` service

## Steps

### Step 1: Open an interactive attacker shell

Run on the host:

```bash
./scripts/compose.sh --scenario pbx2 run --rm attacker sh
```

`PUBLIC_IPV4` is already set in this shell.

### Step 2: Probe the RTP range

In the attacker shell:

```bash
rtpbleed $PUBLIC_IPV4 35000 40000 --duration 6 --first
exit
```

This sends RTP probes from the bridge-networked attacker container against `pbx2`'s public media range.

### Step 3: Observe the leaked RTP response

Look for output like:

```text
RTP response from <IP>:<port>
```

The exact port will vary. A positive RTP response confirms that `rtpproxy` forwarded real media to an attacker source that is not part of the call.

## What's happening

`pbx2` continuously generates background calls to extension `1300`, so RTP is already flowing through `rtpproxy`'s public ports before you do anything. The `rtpbleed` helper sprays RTP probes across the configured range and listens for returned RTP packets, aiming to bleed one or more of those active call-generator streams.

This works because of how `rtpproxy` learns endpoint addresses. When a call is set up, `rtpproxy` allocates a pair of public ports and records the source address of the RTP packets arriving on each leg. From then on, it forwards the other leg's media back to that learned address. A well-timed probe reaching one of those ports can replace the legitimate learned address with the attacker's source, and `rtpproxy` then sends the other leg's media to the attacker. The attacker receives live media without being part of the call.

## Mitigation

- Enforce strict source validation in `rtpproxy` so packets from unexpected source IPs or ports are dropped instead of re-learned as the new endpoint
- Where the deployment does not need dynamic source learning (for example, clients that use STUN correctly or are not behind NAT), disable learning and pin media to the SDP-advertised address
- Use SRTP to protect media confidentiality, but note that RTP bleed may still work as a denial-of-service vector even when the leaked media is encrypted
- Limit RTP exposure to trusted networks and expected peers
