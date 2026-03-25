# Testing

This document is the canonical entrypoint for DVRTC verification commands.

The `testing` and `attacker` Compose services are one-off runner services. Use them with `docker compose run --rm ...`; they are not part of the normal long-lived stack started by `docker compose up -d`. Both services bind-mount `./artifacts` to `/work` inside the container, so output files persist on the host.

## Prerequisites

- Bring the main stack up first with `docker compose up -d`.
- Pull or otherwise reference the explicit release tag from `VERSION` when you are validating published images.
- Build the local test images with `--profile testing` when you are working from `docker-compose.dev.yml`. If you are using the published images from `docker-compose.yml`, no build step is needed.
- Use `127.0.0.1` for commands run inside the host-networked `testing` runner.
- Use `PUBLIC_IPV4` from `.env` for host-shell checks and the bridge-networked `attacker` runner.
- On macOS with Colima, host-shell checks still use `PUBLIC_IPV4`; only the `testing` runner uses `127.0.0.1`.

## Primary Commands

Smoke check from the host-local testing runner:

```bash
./scripts/testing-smoke.sh
```

Full host-local regression run:

```bash
./scripts/testing-run-all.sh
```

Bridge-network attacker-vantage regression run:

```bash
./scripts/attacker-run-all.sh
```

These wrappers map directly to the underlying Compose commands:

```bash
docker compose run --rm testing testing-smoke
docker compose run --rm testing testing-run-all
docker compose run --rm attacker attacker-run-all
```

For release validation, run the stack against the published, versioned images rather than a floating `latest` image.

## Image Builds

When rebuilding the test images locally, include the `testing` profile:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml --profile testing build testing attacker
```

## Which Target To Use

- `testing-smoke`: quick post-start verification from the host-networked `testing` runner.
- `testing-run-all`: full host-network verification from the host-networked `testing` runner.
- `attacker-run-all`: remote-vantage verification from the bridge-networked `attacker` runner.

The wrappers are thin entrypoints to the shared `testing` image used by both `testing` and `attacker`.
