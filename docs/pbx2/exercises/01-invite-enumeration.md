# Exercise 1: INVITE-Based SIP Enumeration

## Goal

Use `sipvicious_svwar` with `-m INVITE` to identify valid `pbx2` extensions from unauthenticated `INVITE` responses.

## Prerequisites

- DVRTC running: `./scripts/compose.sh --scenario pbx2 up -d`
- The `attacker` service available for a remote vantage point

## Steps

### Step 1: Open an interactive attacker shell

Run on the host:

```bash
./scripts/compose.sh --scenario pbx2 run --rm attacker sh
```

`PUBLIC_IPV4` is already set in this shell.

### Step 2: Probe the default classification set

In the attacker shell:

```bash
sipvicious_svwar -m INVITE -e 1200,1000,9999 udp://$PUBLIC_IPV4:5060 -v
```

Look for:

- `1200` reported as found with `noauth`
- `1000` reported as found with `weird`
- `9999` not reported as found

### Step 3: Scan a larger range

In the attacker shell:

```bash
sipvicious_svwar -m INVITE -e 1000-1005,1200,9999 udp://$PUBLIC_IPV4:5060 -v
```

Expected hits in the default lab state are `1000` and `1200`. The rest of `1001-1005` and `9999` should not be reported as found.

### Step 4: Inspect an invalid extension

In the attacker shell:

```bash
sipvicious_svwar -m INVITE -e 9999 udp://$PUBLIC_IPV4:5060 -v --debug
exit
```

`9999` should not be reported as found. In the debug output, look for the final `480 Temporarily Unavailable` with `Reason: Q.850;cause=16;text="NORMAL_CLEARING"`.

## What's happening

In `pbx2`, OpenSIPS forwards unauthenticated `INVITE` requests to FreeSWITCH, and FreeSWITCH leaks target state through different final outcomes.

`svwar` fingerprints the final `INVITE` response instead of only the initial provisional reply. In the default lab state, `1200` answers with `200 OK`, `1000` reaches a known user path and fails with `480` plus `USER_NOT_REGISTERED`, and `9999` falls through the invalid-extension path and fails with `480` plus `NORMAL_CLEARING`.

## Mitigation

- Normalize SIP responses for valid and invalid targets at the proxy edge
- Require authentication or trusted-network access before forwarding unauthenticated `INVITE` traffic
- Rate-limit and alert on sequential SIP probing across extension ranges
- Monitor SIP logs for repeated `INVITE` scans that vary only by target user
