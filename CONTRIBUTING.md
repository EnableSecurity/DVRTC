# Contributing to DVRTC

DVRTC is source-available, but this project is maintainer-driven. We are not actively seeking general unsolicited pull requests.

## Start With An Issue

If you find a bug, documentation problem, or have an idea for a new scenario, vulnerability, or exercise, open an issue in the tracker associated with the repository copy you are using.

Include:

- a clear description of the problem or proposal
- reproduction steps when relevant
- expected versus actual behavior
- environment details
- relevant logs, captures, or screenshots

## Pull Requests

Unsolicited pull requests may be closed without review.

If we explicitly invite or pre-approve a contribution:

1. Open or reference the issue first.
2. Keep the change focused and atomic.
3. Preserve intentionally vulnerable behavior unless the task is specifically to change it.
4. Test the change locally before submitting it.
5. Be prepared to sign the contributor agreement in [CLA.md](CLA.md) before acceptance.

## Testing Expectations

When a change touches Dockerfiles, service configuration, exercises, or the testing toolchain, validate it with the repo's normal workflow. Use [TESTING.md](TESTING.md) for the current smoke and regression commands.

```bash
docker compose up -d
docker compose ps
docker compose logs
./scripts/testing-smoke.sh
./scripts/testing-run-all.sh
./scripts/attacker-run-all.sh
```

These wrapper scripts call the underlying `docker compose run --rm` commands. See [TESTING.md](TESTING.md) for the equivalent raw Compose invocations.

If you need to rebuild images locally, use the maintainer workflow in [docs/development.md](docs/development.md), including the `linux/amd64` requirement and the `testing` profile rules.

## Project-Specific Guidelines

- Mark intentionally vulnerable settings inline with `# INTENTIONALLY VULNERABLE: <explanation>`.
- Keep `docker-compose.yml` runtime-oriented and put local rebuild definitions in `docker-compose.dev.yml`.
- Keep build contexts under `build/`.
- When writing or updating exercises, start from [docs/EXERCISE-TEMPLATE.md](docs/EXERCISE-TEMPLATE.md).
- Prefer environment variables for configurable values and avoid hardcoding new secrets.
- Keep docs concise, repo-specific, and aligned with the current stack behavior.
