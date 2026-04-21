# Exercise N: Title

## Goal

One or two sentences: what you will do and what vulnerability you are exploiting.

## Prerequisites

- DVRTC running, usually with `./scripts/compose.sh --scenario pbx1 up -d`
- Any services that the exercise depends on
- Tools needed (e.g. sipvicious, Wireshark)

## Steps

Use the simplest command that demonstrates the behavior. Do not add extra flags or arguments unless they are required for the step to work or materially help the learning goal.

Prefer the `attacker` service for remote-facing attack exercises so the source IP stays separate from the DVRTC host.
Prefer the `testing` service for packet capture, sniffing, or other host-local diagnostics that need host networking.

**Networking difference:** `testing` uses host networking (`--network host`), so it shares the host's network stack and can capture traffic on host interfaces or reach services on `127.0.0.1`. `attacker` uses bridge networking, giving it a separate IP address that simulates a remote attacker. Choose `attacker` when the exercise should demonstrate an attack from an external vantage point; choose `testing` when the exercise requires direct host-level access (e.g., packet capture, RTP sniffing, or loopback-only service checks).

State whether each command runs on the host, in `testing`, or in `attacker`.
Files written under `/work` from `testing` or `attacker` persist to the host's `artifacts/` directory.

If an exercise needs several consecutive commands from one service, prefer starting one interactive shell in that service with `./scripts/compose.sh --scenario ... run --rm ...` and running the tool commands inside it instead of repeating the wrapper command on every step.

### Step 1: Description

```bash
command here
```

Expected output or what to look for.

### Step 2: Description

```bash
command here
```

### Step 3: Verify

How to confirm the attack worked.

## What's happening

Brief technical explanation of why this works (the vulnerability mechanism). Keep it to one or two paragraphs.

## Mitigation

Bullet list of how to defend against this in production.
