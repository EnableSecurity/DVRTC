# Exercise 7: RTP Flood / Recording Growth

## Goal

Flood the negotiated RTP target during a call and confirm that the `.pcap` recording grows rapidly.

## Prerequisites

- DVRTC running: `./scripts/compose.sh --scenario pbx2 up -d`
- The `attacker` service available for a remote vantage point

## Steps

### Step 1: Open an interactive attacker shell

Run on the host:

```bash
./scripts/compose.sh --scenario pbx2 run --rm attacker sh
```

### Step 2: Run the RTP flood helper

In the attacker shell:

```bash
rtpflood --host $PUBLIC_IPV4 --recordings-host $PUBLIC_IPV4 --extension 1200
```

The tool places a call to extension `1200` (the echo service), then floods the media path with oversized RTP payloads while the call is active. Look for `RTP flood susceptibility confirmed`.

### Step 3: Check the recording spool

In the attacker shell:

```bash
curl -fsS http://$PUBLIC_IPV4/recordings/spool/ | grep rtpflood
exit
```

You should see a large `.pcap` entry created by the flood.

## What's happening

`pbx2` records every anchored RTP session through `rtpproxy`. During an active call, an attacker can send large volumes of RTP payload toward the negotiated media target and cause the recording to grow much faster than the legitimate call would.

The vulnerability here is storage and capture abuse, not just bandwidth use. The flood inflates what gets written to disk.

## Mitigation

- Validate RTP source and rate more strictly
- Cap per-call recording growth and overall recording retention
- Alert on unusual packet rates or recording-size jumps
- Avoid unconditional recording on untrusted public media paths
