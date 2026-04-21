# Exercise 4: SIP Digest Leak

## Goal

Exploit extension `2000` to capture a `Proxy-Authorization: Digest` header from an in-dialog `BYE`.

## Prerequisites

- DVRTC running: `./scripts/compose.sh --scenario pbx2 up -d`
- The `attacker` service available for a remote vantage point
- The `baresip-digestleak` helper running so extension `2000` stays registered

## Steps

### Step 1: Open an interactive attacker shell

Run on the host:

```bash
./scripts/compose.sh --scenario pbx2 run --rm attacker sh
```

### Step 2: Run the digest leak attack

In the attacker shell:

```bash
digestleak $PUBLIC_IPV4 2000 | tee /work/pbx2-digestleak.txt
```

Look for the final `Digest leak completed successfully` line and the `john`-compatible `$sip$*...` output.

### Step 3: Extract the captured SIP hash line

In the attacker shell:

```bash
grep '^\$sip\$' /work/pbx2-digestleak.txt
exit
```

The output should include a `john`-compatible SIP hash line. To crack it offline, continue with [Exercise 5](05-offline-credential-cracking.md).

## What's happening

OpenSIPS keeps extension `2000` reachable for the digest-leak demonstration. After the helper answers and sends `BYE`, the attacker challenges that in-dialog request with `407 Proxy Authentication Required`.

The client retries the `BYE` with `Proxy-Authorization: Digest ...`, and OpenSIPS relays that authenticated request back toward the attacker. That leaks digest material that can be cracked offline.

## Mitigation

- Do not relay attacker-originated in-dialog `401` or `407` challenges to registered clients
- Do not forward authenticated in-dialog requests back toward untrusted callers
- Isolate special demo users like `2000` from normal public call paths
- Monitor for unusual `BYE` challenge behavior and repeated failed call teardown flows
