# Exercise 9: FreeSWITCH Lua SQL Injection

## Goal

Exploit the intentionally vulnerable FreeSWITCH Lua `freeswitch.Dbh` script behind `2001` by injecting SQL through the called SIP URI and reaching the hidden internal-only `9000` service.

## Prerequisites

- DVRTC running: `./scripts/compose.sh --scenario pbx2 up -d`
- The `attacker` service available for a remote vantage point, with `freeswitch-lua-sqli` on `PATH`
- Optional, for the manual client test: Zoiper registered as extension `1000` with password `1500`

## Steps

### Step 1: Open an interactive attacker shell

Run on the host:

```bash
./scripts/compose.sh --scenario pbx2 run --rm attacker sh
```

### Step 2: Run the automated SQL injection check

In the attacker shell:

```bash
freeswitch-lua-sqli --host $PUBLIC_IPV4 --extension 2001
exit
```

Confirm three things in the output:

- a direct call to `9000` does not work
- a normal call to `2001` reaches the public HAL service
- the injected called URI reaches the hidden `9000` service and produces the distinct `183` early-media response

### Step 3: Inspect the injected URI

The check above already sends a crafted called SIP URI. The injected user part is:

```text
2001'/**/AND/**/0/**/UNION/**/SELECT/**/target,scope/**/FROM/**/did_routes/**/WHERE/**/did='9000
```

This `/**/` form is one of two equivalent encodings. Percent-encoding the spaces as `%20` works the same way - both forms survive SIP URI parsing and produce the same SQL.

If you reproduce the issue with another SIP client, that string needs to appear in the called URI. The payload suppresses the normal `2001` row with `AND 0` and then asks SQLite for the target and scope assigned to DID `9000`. The final quote is omitted because the vulnerable Lua script appends the closing quote itself.

### Step 4: Trigger it from Zoiper

If you want to reproduce the same issue manually in Zoiper, use a plain SIP account configured like this or equivalent:

- Domain: the actual IP address of the DVRTC server
- Username: `1000`
- Password: `1500`
- No auth username override
- No outbound proxy

Then:

1. Click or tap the text field above the keypad so you can enter symbols instead of only digits.
2. Call `2001` first and confirm that it reaches the public HAL service.
3. Then dial this user part:

```text
2001'/**/AND/**/0/**/UNION/**/SELECT/**/target,scope/**/FROM/**/did_routes/**/WHERE/**/did='9000
```

Zoiper may also accept the simpler payload below, since it percent-encodes the spaces automatically as it builds the SIP URI:

```text
2001' AND 0 UNION SELECT target, scope FROM did_routes WHERE did='9000
```

The expected result is that the normal `2001` call reaches the public HAL service, while the injected call reaches the hidden `9000` service and plays the access-granted clip.

### Step 5: Verify in the logs

On the host:

```bash
./scripts/compose.sh --scenario pbx2 logs freeswitch
```

Look for the logged Lua query and the `Lua SQLi DID mapping redirected` message showing the call was redirected to `9000`.

## What's happening

Extension `2001` runs a Lua script based on the FreeSWITCH `freeswitch.Dbh` example. The script concatenates the caller-controlled called SIP URI user part into a SQLite query and stores the returned route target and scope in channel variables. A normal lookup for `2001` returns the public `2001/public` route target, which sends the call to the public HAL service, so the service is useful without exploitation.

The same routing table also contains an internal row for `9000`, but direct public calls to `9000` are still blocked by dialplan policy because the vulnerable lookup only runs on the public `2001` entrypoint. A malicious called URI such as `2001'/**/AND/**/0/**/UNION/**/SELECT/**/target,scope/**/FROM/**/did_routes/**/WHERE/**/did='9000` changes the SQL result so the call uses the `9000/internal` target returned from the same table and is transferred to the hidden internal-only service instead. The public `2001` path plays the HAL introduction followed by "I'm sorry, Dave. I'm afraid I can't do that.", while the hidden `9000` path answers the call, plays the access-granted clip, and emits a distinct `183` early-media response before the final `200 OK`. The vulnerable behavior is visible over the network because `9000` is present in the same routing database but is not directly reachable from the public side.

## Mitigation

- Replace `freeswitch.Dbh` with `lsqlite3` for application databases like DID route tables. `lsqlite3` exposes the full SQLite `prepare`/`bind`/`step` API, so the vulnerable query becomes `db:prepare("SELECT target, scope FROM did_routes WHERE did = ?")` with `stmt:bind_values(dialed)` — real parameter binding, not string escaping. `freeswitch.Dbh` has no parameterized query support and no escape function. `luasql-sqlite3` offers `conn:escape()` (backed by `sqlite3_mprintf("%q")`) which is better than nothing, but is still string-level escaping, not bind parameters.
- Restrict or remove debug/demo dialplan logic from production systems
- Validate transfer targets before using database-derived channel variables
