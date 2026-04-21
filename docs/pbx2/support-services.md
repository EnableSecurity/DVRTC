# Support Services Reference

## Role In Scenario

These services make `pbx2` repeatable:

- automated callers keep media targets active
- a dedicated helper keeps the digest-leak flow reproducible
- a background cleaner prevents unbounded recording growth
- test containers provide host-local and remote-vantage validation tooling

## Services

### `baresip-callgen-pbx2`, `baresip-callgen-b-pbx2`, `baresip-callgen-c-pbx2`

Role:
Generate staggered calls to extension `1300` so RTP bleed and traffic-analysis exercises have active media to observe.

Current behavior:
- three call generators start with delays of `0`, `8`, and `16` seconds
- each call runs for `20` seconds by default
- each instance uses the `sipcaller1` account with the generated `.env` password
- the containers loop continuously so the target stays active during exercises

Key files:
- `build/baresip-callgen/accounts`
- `build/baresip-callgen/config`
- `build/baresip-callgen/callgen.sh`

### `baresip-digestleak-pbx2`

Role:
Registers extension `2000`, auto-answers calls, and quickly hangs up to make the digest-leak exercise reproducible.

Current behavior:
- the helper registers `2000` through the loopback-only path enforced by OpenSIPS and answers a digest challenge with the fixed `2000` password
- a background loop sends hangup commands every `2` seconds through `ctrl_tcp`
- the helper starts the hangup loop after a short startup delay so the account is already online

Key files:
- `build/baresip-digestleak/accounts`
- `build/baresip-digestleak/config`
- `build/baresip-digestleak/run.sh`

### `recordingscleaner`

Role:
Limits `.pcap` recording growth during repeated RTP flood testing and normal scenario use.

Current behavior:
- watches only the top level of `/recordings`
- does not descend into `/recordings/spool`
- scans every second
- trims files older than `30m`
- caps per-file size at `1GB`
- caps total directory size at `5GB`
- keeps at most `300` files so the three continuous call generators retain about 30 minutes of completed captures with a small buffer for other calls

Key file:
- `build/voicemailcleaner/voicemail_cleaner.py`

### `testing` and `attacker`

Role:
Provide host-local and remote-vantage validation tooling under the `testing` profile.

Current behavior:
- `testing` is the host-networked runner used for local smoke and regression checks
- `attacker` is the bridge-networked runner used for remote-vantage checks
- both are one-off services and are usually absent from `docker compose ps`
- the regression path enables the checks relevant to the `pbx2` attack surfaces, including RTP flood

Key files:
- `build/testing/Dockerfile`
- `build/testing/run-all.sh`
- `build/testing/attacker-run-all.sh`
- `build/testing/smoke.sh`
- `build/testing/scripts/`

## Related Documentation

- [Overview](overview.md)
- [Architecture](architecture.md)
- [FreeSWITCH Configuration](freeswitch.md)
- [Nginx Reference](nginx.md)
