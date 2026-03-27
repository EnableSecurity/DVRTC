# Development and Local Builds

This document covers maintainer-oriented local rebuild workflows. The default runtime path in `docker-compose.yml` uses published, versioned images and remains the recommended path for normal lab usage.

## When To Use This

Use the development override when you need to:

- rebuild one or more service images from `build/`
- test changes to Dockerfiles or embedded service configuration
- work on the `testing` or `attacker` toolchain locally

## Platform Constraints

All DVRTC images must be built for `linux/amd64`. Every service in `docker-compose.yml` sets `platform: linux/amd64`, so Compose enforces the correct platform automatically when both compose files are used together. No `DOCKER_DEFAULT_PLATFORM` env var is needed.

The `testing` and `attacker` services are behind the `testing` Compose profile. When building either image, include `--profile testing` so Compose applies the profile-gated service definition.

The repo-root `VERSION` file is the release source of truth for published runtime images. Local rebuilds should match the current release tag unless you are intentionally testing a version bump in progress.

Use `./scripts/dev-compose.sh` for maintainer rebuilds instead of calling `docker compose -f docker-compose.yml -f docker-compose.dev.yml` directly. The wrapper defaults `DVRTC_VERSION` from `VERSION` and `VCS_REF` from git so local rebuild metadata stays aligned with the current repo state.

Published runtime tags are not mutable release scratch space. Once a release image has been pushed for a given `VERSION`, do not repush changed image contents under that same tag. If a repo-owned runtime image changes and you want to publish it, bump `VERSION` and publish the full release image set so the runtime compose file remains internally consistent.

## Local Rebuild Workflow

Rebuild the normal service set:

```bash
./scripts/dev-compose.sh build
./scripts/dev-compose.sh up -d
```

Rebuild a single service:

```bash
./scripts/dev-compose.sh build kamailio
```

Rebuild the profile-gated test images:

```bash
./scripts/dev-compose.sh --profile testing build testing attacker
```

If you intentionally want non-release metadata in the rebuilt images, override `DVRTC_VERSION` explicitly:

```bash
DVRTC_VERSION=dev ./scripts/dev-compose.sh build nginx
```

Avoid running raw `docker compose -f docker-compose.yml -f docker-compose.dev.yml build ...` without setting `DVRTC_VERSION`. That path falls back to `dev` metadata while still tagging the rebuilt image with the runtime image name, which can make later `docker compose up -d` runs look like published release containers even though `/__version` reports `dev`.

## Verification

After rebuilding, validate the environment and bring the stack up:

```bash
./scripts/validate_env.sh
./scripts/dev-compose.sh up -d
docker compose ps
docker compose logs [service]
./scripts/testing-smoke.sh
./scripts/testing-run-all.sh
```

Run `validate_env.sh` as a pre-flight check before bringing the stack up to catch missing variables, certificates, or addressing issues early.

If the change affects startup, networking, or service behavior, do a fresh stack cycle and inspect logs before and after the test run. For broader validation, use the checks documented in the [README](../README.md) and [TESTING.md](../TESTING.md).

For release consistency checks, run the image-reference validator after updating the stack version and before publishing exported artifacts.

For maintainers building release-tagged images outside the normal dev override flow, use `./scripts/build-release-images.sh` and `./scripts/build-latest-stubs.sh`. The expected release flow is: bump `VERSION`, update runtime image references, run `./scripts/build-release-images.sh --push`, then run `./scripts/validate_image_refs.sh`.

## Return To Published Images

If you want to leave the local rebuild path and return to the published runtime images pinned in `docker-compose.yml`, pull the published tags and force-recreate the affected services:

```bash
docker compose pull nginx
docker compose up -d --force-recreate nginx
```

Use the same pattern for any other locally rebuilt service that should go back to the published image.

## Related Documentation

- [README](../README.md)
- [Contributing](../CONTRIBUTING.md)
- [Troubleshooting](troubleshooting.md)
