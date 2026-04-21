# Exercise 8: SIP Flood

## Goal

Send repeated SIP requests to the public edge and confirm that `pbx2` does not actively throttle them.

## Prerequisites

- DVRTC running: `./scripts/compose.sh --scenario pbx2 up -d`
- The `attacker` service available for a remote vantage point

## Steps

### Step 1: Open an interactive attacker shell

Run on the host:

```bash
./scripts/compose.sh --scenario pbx2 run --rm attacker sh
```

### Step 2: Run the flood check

In the attacker shell:

```bash
dvrtc-checks sip-flood --host $PUBLIC_IPV4 --requests 200
```

Look for `SIP flood susceptibility confirmed`.

### Step 3: Repeat with a larger burst

In the attacker shell:

```bash
dvrtc-checks sip-flood --host $PUBLIC_IPV4 --requests 500
exit
```

The edge should continue responding rather than returning throttling errors such as `503`.

## What's happening

The `pbx2` SIP edge does not implement active request throttling in the public path. A burst of unauthenticated requests therefore gets processed and answered instead of being rate-limited.

This exercise demonstrates flood susceptibility, not a full denial-of-service threshold. It confirms the lack of basic edge throttling.

## Mitigation

- Add proxy-side rate limiting for unauthenticated SIP traffic
- Detect and block rapid sequential requests from the same source
- Separate registration, call setup, and diagnostic traffic into different limit buckets
- Monitor for unusual SIP request volume and response spikes
