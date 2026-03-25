# Support Services Reference

## Role In Scenario

These services make the scenario repeatable:

- automated callers keep RTP targets active
- a dedicated endpoint keeps the digest-leak flow reproducible
- background cleaners prevent unbounded storage growth
- export jobs turn captured data into a browsable web artifact
- test containers provide local and remote validation tooling

## Services

### `baresip-callgen`, `baresip-callgen-b`, `baresip-callgen-c`

Role:
Generate staggered calls to extension `1300` so RTP bleed has an active media source.

Current behavior:
- three call generators start with delays of `0`, `8`, and `16` seconds
- each call runs for `20` seconds by default
- the containers loop continuously so the target stays active during exercises

Key files:
- `build/baresip-callgen/accounts`
- `build/baresip-callgen/config`
- `build/baresip-callgen/callgen.sh`

### `baresip-digestleak`

Role:
Registers extension `2000`, auto-answers calls, and quickly hangs up to make the digest-leak exercise reproducible.

Current behavior:
- a helper loop sends hangup commands every `2` seconds after a short startup delay
- the helper keeps `2000` registered so Kamailio can hand out repeatable digest challenges

Key files:
- `build/baresip-digestleak/accounts`
- `build/baresip-digestleak/config`
- `build/baresip-digestleak/run.sh`

### `voicemailcleaner`

Role:
Limits voicemail growth during repeated testing.

Current behavior:
- scans every second
- trims files older than `1h`
- caps per-file size at `1GB`
- caps per-directory size at `5GB`
- keeps at most `100` files per directory

Key file:
- `build/voicemailcleaner/voicemail_cleaner.py`

### `mysqlclient`

Role:
Exports database-backed user-agent data into a JSON file under the Nginx document root.

Current behavior:
- refreshes the export once per second
- keeps retrying until the MySQL schema is initialized

Key files:
- `build/mysqlclient/dump-uas.py`
- `build/mysqlclient/run.sh`

### `dbcleaner`

Role:
Prevents the `useragents` table from growing indefinitely during repeated exercises.

Current behavior:
- retries until the schema exists
- deletes all rows from `useragents` every hour

Key file:
- `build/dbcleaner/run.sh`

### `testing` and `attacker`

Role:
Provide host-local and remote-vantage validation tooling under the `testing` profile.

Current behavior:
- `testing` is the host-networked runner used for local smoke and regression checks
- `attacker` is the bridge-networked runner used for remote-vantage checks
- both are one-off services and are usually absent from `docker compose ps`

Key files:
- `build/testing/Dockerfile`
- `build/testing/run-all.sh`
- `build/testing/attacker-run-all.sh`
- `build/testing/smoke.sh`
- `build/testing/scripts/`

## Related Documentation

- [Overview](overview.md)
- [Architecture](architecture.md)
- [Asterisk Configuration](asterisk.md)
- [MySQL Reference](mysql.md)
- [Nginx Reference](nginx.md)
