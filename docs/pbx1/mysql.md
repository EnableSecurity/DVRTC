# MySQL Reference

## Role In Scenario

MySQL backs the `useragents` database used for SIP header logging and injection exercises. It is intentionally exposed on the host and intentionally uses weak application credentials for training purposes.

- default TCP port: `23306`
- network mode: host
- Unix socket shared through the `mysqlsock` volume
- root password generated into `.env`
- application user: `kamailio`
- schema creation and seeded fake customer data happen in `build/kamailio/run.sh`

## Key Files

| File | Purpose |
|------|---------|
| `build/mysql/validate-and-start.sh` | startup validation for required environment |
| `build/mysql/Dockerfile` | image customizations |
| `compose/pbx1.yml` | exposed port, credentials, and service wiring |
| `build/mysqlclient/dump-uas.py` | exports tracked user-agent data to JSON |
| `build/dbcleaner/run.sh` | periodically truncates the `useragents` table |
| `build/kamailio/run.sh` | creates the `useragents` schema and seeds fake customer data |

## Intentionally Vulnerable Behavior

- host-exposed database port
- weak hardcoded application password (`kamailiorw`)
- `useragents` stores attacker-controlled SIP header content
- `customers` contains fake sensitive data for extraction exercises
- `kamailio` gets write access to `useragents.useragents` and read-only access to `useragents.customers`

SIP endpoint authentication is not stored here; it lives in Asterisk configuration.

## Verification

```bash
./scripts/compose.sh --scenario pbx1 run --rm testing sqli --host 127.0.0.1 --extension 1000
./scripts/compose.sh --scenario pbx1 logs db
```

## Related Documentation

- [Overview](overview.md)
- [Architecture](architecture.md)
- [Kamailio Configuration](kamailio.md)
- [Support Services](support-services.md)
