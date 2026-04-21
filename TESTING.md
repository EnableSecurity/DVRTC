# Testing

This document is the canonical entrypoint for DVRTC verification commands.

The `testing` and `attacker` Compose services are one-off runner services. Prefer `./scripts/compose.sh --scenario ... run --rm ...` or the dedicated wrapper scripts; they are not part of the normal long-lived stack started by `./scripts/compose.sh --scenario pbx1 up -d` or `./scripts/compose.sh --scenario pbx2 up -d`. Both services bind-mount `./artifacts` to `/work` inside the container, so output files persist on the host.

## Prerequisites

- Bring the main stack up first with `./scripts/compose.sh --scenario pbx1 up -d` or `./scripts/compose.sh --scenario pbx2 up -d`.
- Run only one scenario at a time on the same host. `pbx1` and `pbx2` both use host networking for the core RTC services and will conflict on overlapping ports.
- Pull or otherwise reference the explicit release tag from `VERSION` when you are validating published images.
- Build the local test images with `--profile testing` when you are working from the maintainer compose overlays. `./scripts/dev-compose.sh --scenario pbx1 --profile testing build testing attacker` is the preferred path. If you are using the published images from the runtime compose files, no build step is needed.
- Use `127.0.0.1` for commands run inside the host-networked `testing` runner.
- Use `PUBLIC_IPV4` from `.env` for host-shell checks and the bridge-networked `attacker` runner.
- On macOS with Colima, host-shell checks still use `PUBLIC_IPV4`; only the `testing` runner uses `127.0.0.1`.

## Primary Commands

Smoke check from the host-local testing runner:

```bash
./scripts/testing-smoke.sh
./scripts/testing-smoke.sh --scenario pbx2
```

Full host-local regression run:

```bash
./scripts/testing-run-all.sh
./scripts/testing-run-all.sh --scenario pbx2
```

Bridge-network attacker-vantage regression run:

```bash
./scripts/attacker-run-all.sh
./scripts/attacker-run-all.sh --scenario pbx2
```

These wrappers map directly to the corresponding scenario-wrapper commands:

```bash
./scripts/compose.sh --scenario pbx1 run --rm testing testing-smoke
./scripts/compose.sh --scenario pbx1 run --rm testing testing-run-all
./scripts/compose.sh --scenario pbx1 run --rm attacker attacker-run-all
```

For release validation, run the stack against the published, versioned images rather than a floating `latest` image.

## Image Builds

When rebuilding the test images locally, include the `testing` profile:

```bash
./scripts/dev-compose.sh --scenario pbx1 --profile testing build testing attacker
./scripts/dev-compose.sh --scenario pbx2 --profile testing build testing attacker
```

## Which Target To Use

- `testing-smoke`: quick post-start verification from the host-networked `testing` runner.
- `testing-run-all`: full host-network verification from the host-networked `testing` runner.
- `attacker-run-all`: remote-vantage verification from the bridge-networked `attacker` runner.

The wrappers are thin entrypoints to the shared `testing` image used by both `testing` and `attacker`.

Prefer the dedicated wrapper scripts for `testing-smoke`, `testing-run-all`, and `attacker-run-all`. They make the scenario explicit and are the clearest path for routine validation. If you do need the maintainer overlay path after local rebuilds, keep `--scenario` explicit on `./scripts/dev-compose.sh`; the wrapper now passes that scenario through to `testing` and `attacker` `run` commands automatically.

Use `--scenario pbx2` when validating the OpenSIPS/FreeSWITCH/rtpproxy stack.

Equivalent raw runtime commands are `docker compose --project-directory . -p dvrtc-pbx1 -f compose/base.yml -f compose/pbx1.yml up -d` and `docker compose --project-directory . -p dvrtc-pbx2 -f compose/base.yml -f compose/pbx2.yml up -d`, but they are mutually exclusive on the same host for the same reason.
