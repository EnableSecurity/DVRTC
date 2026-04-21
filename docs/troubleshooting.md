# DVRTC Troubleshooting

This guide is intentionally narrow: it focuses on DVRTC's current failure modes instead of generic Docker or operating system setup.

## Start Here

Run these first before chasing a specific symptom:

```bash
# Check service state
./scripts/compose.sh --scenario pbx1 ps

# Validate .env and certificate prerequisites
./scripts/validate_env.sh

# Look at logs for the failing service
./scripts/compose.sh --scenario pbx1 logs kamailio
./scripts/compose.sh --scenario pbx1 logs asterisk
./scripts/compose.sh --scenario pbx1 logs db
./scripts/compose.sh --scenario pbx1 logs nginx
./scripts/compose.sh --scenario pbx1 logs coturn

# Run the baseline smoke test
./scripts/testing-smoke.sh
```

Keep these repo-specific behaviors in mind while reading service state and logs:

- `testing` and `attacker` are behind the `testing` profile, so they do not appear in `docker compose ps` unless you run them explicitly or start the profile.
- `testing` is host-networked and uses `127.0.0.1` for host-local checks; `attacker` is bridge-networked and uses `PUBLIC_IPV4` for remote-vantage checks.
- `certbot` is not useful unless `DOMAIN` and `EMAIL` are set. For normal lab use, self-signed certificates from `./scripts/init-selfsigned.sh` are the expected path.
- plain `docker compose up -d` is not enough to start DVRTC because the base file at `compose/base.yml` does not include a runtime scenario by itself; use `./scripts/compose.sh --scenario pbx1 ...` or `./scripts/compose.sh --scenario pbx2 ...`
- the examples below use `pbx1` service names; when you are troubleshooting `pbx2`, swap in `--scenario pbx2` and the corresponding service names such as `opensips`, `freeswitch`, `rtpproxy`, and `nginx-pbx2`

## Setup And Configuration

### `validate_env.sh` fails

DVRTC expects three setup steps before starting a scenario:

```bash
./scripts/setup_networking.sh
./scripts/generate_passwords.sh
./scripts/init-selfsigned.sh
./scripts/validate_env.sh
./scripts/compose.sh --scenario pbx1 up -d
```

`./scripts/validate_env.sh` checks the current repo assumptions:

- `.env` exists
- `PUBLIC_IPV4` is set to a real IPv4 address
- `MYSQL_ROOT_PASSWORD` and `SIPCALLER1_PASSWORD` were generated
- TLS material exists in `data/certs/`
- `PUBLIC_IPV6`, if set, is a raw IPv6 literal without brackets
- `MYSQL_PORT`, if set, is a valid TCP port

Rerun it after destructive resets or `.env` edits so you catch setup drift immediately.

### `PUBLIC_IPV4` or `PUBLIC_IPV6` is wrong

Symptoms usually look like this:

- SIP registration works inconsistently or fails outright
- no audio or one-way audio
- RTP bleed or TURN exercises fail even though containers are up

Fix the addressing first:

```bash
./scripts/setup_networking.sh
./scripts/validate_env.sh
grep '^PUBLIC_IPV' .env
```

Rules that matter for this repo:

- `PUBLIC_IPV4` must not be a loopback address (`127.x.x.x`), `0.0.0.0`, or `localhost`
- `PUBLIC_IPV6` is optional, but if set it must be a raw IPv6 literal such as `2001:db8::1`
- do not use brackets in `.env`
- do not use `::1` or link-local `fe80::` addresses

### Certificates are missing or unusable

Kamailio, Nginx, and coturn all expect TLS material under `data/certs/`.

For normal lab use:

```bash
./scripts/init-selfsigned.sh
```

For public-domain TLS:

```bash
# Set DOMAIN and EMAIL in .env first
./scripts/init-letsencrypt.sh
```

If TLS or WSS is failing and you are using self-signed certificates, verify the files exist:

```bash
ls -la data/certs/
```

## Service Startup Problems

### Core services are not healthy

The main services to care about are:

- `db`
- `asterisk`
- `rtpengine`
- `kamailio`
- `nginx`
- `coturn`

Start with:

```bash
./scripts/compose.sh --scenario pbx1 ps
./scripts/compose.sh --scenario pbx1 logs db
./scripts/compose.sh --scenario pbx1 logs asterisk
./scripts/compose.sh --scenario pbx1 logs rtpengine
./scripts/compose.sh --scenario pbx1 logs kamailio
./scripts/compose.sh --scenario pbx1 logs nginx
./scripts/compose.sh --scenario pbx1 logs coturn
```

Common current causes:

- setup was incomplete and a required environment variable is empty
- `data/certs/` is missing
- another service on the host is already using SIP, HTTP, HTTPS, TURN, or MySQL ports
- `PUBLIC_IPV4` points to the wrong host address

### One specific service keeps failing

Use the service name directly:

```bash
./scripts/compose.sh --scenario pbx1 logs kamailio
./scripts/compose.sh --scenario pbx1 logs asterisk
./scripts/compose.sh --scenario pbx1 logs rtpengine
./scripts/compose.sh --scenario pbx1 logs db
./scripts/compose.sh --scenario pbx1 logs nginx
./scripts/compose.sh --scenario pbx1 logs coturn
```

Current repo-specific checks:

- `db`: verify `MYSQL_ROOT_PASSWORD` exists in `.env`
- `asterisk`: verify `SIPCALLER1_PASSWORD` exists in `.env`
- `kamailio`: verify both the database and certificates are available
- `nginx`: verify `data/certs/fullchain.pem`, `data/certs/privkey.pem`, and `data/certs/ssl-dhparams.pem` exist
- `coturn`: verify certificates exist and `PUBLIC_IPV4` is correct

### Port conflicts

DVRTC relies on host networking for the core RTC services. If you already have SIP, TURN, HTTP, HTTPS, or MySQL services running on the host, DVRTC may fail to bind.
This also means `pbx1` and `pbx2` cannot run at the same time on the same host: the two scenarios reuse overlapping host ports and RTP ranges.

The most important ports are:

- `5060` UDP/TCP for SIP (Kamailio)
- `5061` TCP for SIP/TLS (Kamailio)
- `5090` TCP for SIP (Asterisk, Kamailio routes to this)
- `8000` TCP for WS
- `8443` TCP for WSS
- `3478` UDP/TCP for TURN/STUN
- `80` and `443` TCP for Nginx
- `23306` TCP for MySQL by default
- `10000-15000` UDP for Asterisk RTP
- `35000-40000` UDP for rtpengine

Quick checks:

```bash
sudo lsof -nP -i :5060
sudo lsof -nP -i :5061
sudo lsof -nP -i :3478
sudo lsof -nP -i :80
sudo lsof -nP -i :443
sudo lsof -nP -i :23306
```

## Access Problems

### SIP, TLS, WS, or WSS registration fails

Use the repo's transport checks instead of guessing:

```bash
./scripts/compose.sh --scenario pbx1 run --rm testing dvrtc-checks sip-transport --host 127.0.0.1
./scripts/compose.sh --scenario pbx1 run --rm testing dvrtc-checks wss-register --host 127.0.0.1
```

`wss-register` applies to `pbx1`. When troubleshooting `pbx2`, use `./scripts/compose.sh --scenario pbx2 run --rm testing dvrtc-checks sip-transport --scenario pbx2 --host 127.0.0.1` instead because `pbx2` does not expose a browser/WebRTC WSS endpoint.

If only TLS or WSS is failing, check certificates first:

```bash
ls -la data/certs/
./scripts/compose.sh --scenario pbx1 logs kamailio
./scripts/compose.sh --scenario pbx1 logs nginx
```

If the stack is reachable on IPv4 but not IPv6, re-check `PUBLIC_IPV6` in `.env`. When you browse or test an IPv6 HTTP endpoint, use brackets in the URL, for example `http://[2001:db8::1]/`.

### The web interface is not reachable

Check the advertised address from `.env` first:

```bash
grep '^PUBLIC_IPV4=' .env
. ./.env
curl "http://${PUBLIC_IPV4}/"
./scripts/compose.sh --scenario pbx1 logs nginx
```

Platform note:

- on a native Linux Docker host, `curl http://127.0.0.1/` is also a useful local-bind check
- on macOS with Colima or any other Linux VM workflow, prefer the bridged `PUBLIC_IPV4` from `.env` for host-side checks because it matches the VM's real advertised service identity
- on current Colima releases, `127.0.0.1` on macOS may also reach forwarded services, but that is a convenience path rather than the canonical address for the stack
- if you specifically want to test loopback inside a Colima VM, run `colima ssh -- curl http://127.0.0.1/`

For HTTPS with self-signed certificates:

```bash
curl -k "https://${PUBLIC_IPV4}/"
```

If the advertised-address check fails, the problem is usually firewalling, a wrong `PUBLIC_IPV4`, or testing the wrong network namespace.

## Media, RTP, And TURN

### No audio, one-way audio, or RTP exercises fail

For DVRTC, the usual causes are:

- `PUBLIC_IPV4` is wrong
- RTP UDP ranges are blocked
- the host platform does not support the required host-networking model
- the call generators are not active, so there is no RTP traffic to inspect

Check the current state:

```bash
grep '^PUBLIC_IPV' .env
./scripts/compose.sh --scenario pbx1 logs asterisk
./scripts/compose.sh --scenario pbx1 logs rtpengine
./scripts/compose.sh --scenario pbx1 logs baresip-callgen
./scripts/compose.sh --scenario pbx1 logs baresip-callgen-b
./scripts/compose.sh --scenario pbx1 logs baresip-callgen-c
./scripts/compose.sh --scenario pbx1 run --rm testing dvrtc-checks callgen-active --host 127.0.0.1
./scripts/compose.sh --scenario pbx1 run --rm testing dvrtc-checks rtp-bleed --host 127.0.0.1
```

If SIP works but media does not, fix addressing and UDP reachability before changing service configs.

### TURN checks fail

The current TURN-specific check is:

```bash
./scripts/compose.sh --scenario pbx1 logs coturn
. ./.env
./scripts/compose.sh --scenario pbx1 run --rm attacker turn-probe tcp-http-get --host "$PUBLIC_IPV4" --username user --password joshua --peer 127.0.0.1 --path /secret/
```

If you want the broader remote-vantage suite after the TURN probe passes, run `./scripts/attacker-run-all.sh`.

Verify these repo assumptions:

- coturn is listening on `3478`
- the weak credential pair is `user` / `joshua`
- `PUBLIC_IPV4` is reachable from the attacking client

## Local Development Builds

If the problem only appears after rebuilding images locally, use the maintainer workflow in [development.md](development.md).

The most common mistake is forgetting `--profile testing` when building `testing` or `attacker`. The `platform: linux/amd64` constraint is set on the scenario runtime services, so no `DOCKER_DEFAULT_PLATFORM` env var is needed when the base and scenario compose files are used together.

## Resetting The Lab

If you want to restart the services without deleting state:

```bash
docker compose --project-directory . -p dvrtc-pbx1 -f compose/base.yml -f compose/pbx1.yml down
./scripts/compose.sh --scenario pbx1 up -d
```

If you want a clean reset and are willing to delete voicemail, MySQL state, and generated web artifacts:

```bash
docker compose --project-directory . -p dvrtc-pbx1 -f compose/base.yml -f compose/pbx1.yml down -v
./scripts/setup_networking.sh
./scripts/generate_passwords.sh
./scripts/init-selfsigned.sh
./scripts/validate_env.sh
./scripts/compose.sh --scenario pbx1 up -d
```

Use the destructive reset only when you are explicitly okay with losing lab state.

## Platform Constraints

DVRTC's core services use host networking. The supported path is a Linux Docker host.

- direct Docker Desktop deployment on macOS or Windows is not supported
- on macOS, use the Colima workflow in [colima-setup.md](colima-setup.md) or run DVRTC inside a Linux VM
- if you are rebuilding images locally on Apple Silicon, keep the `linux/amd64` requirement from [development.md](development.md) in mind

## Getting Help

When you report a problem, include the commands that answer these questions:

```bash
./scripts/compose.sh --scenario pbx1 ps
./scripts/validate_env.sh
./scripts/compose.sh --scenario pbx1 logs kamailio
./scripts/compose.sh --scenario pbx1 logs asterisk
./scripts/compose.sh --scenario pbx1 logs db
./scripts/compose.sh --scenario pbx1 logs nginx
./scripts/compose.sh --scenario pbx1 logs coturn
./scripts/testing-smoke.sh
```

That output is usually enough to distinguish setup, port-binding, certificate, signaling, and RTP problems in the current repo.
