# Nginx Reference

## Role In Scenario

Nginx provides the HTTP and HTTPS surface for `pbx1`. It serves the default landing page, browser softphone, voicemail artifacts, exported user-agent data, and the Let's Encrypt webroot flow.

- ports: `80/TCP` and `443/TCP`
- network mode: host
- certificates are read from `data/certs`
- the shared `voicemail`, `wwwlog`, and `acme-challenge` volumes are mounted into the document root
- the running image also exposes release metadata at `/__version`

## Key Files

| File | Purpose |
|------|---------|
| `build/nginx/config/sites-available/default` | site definitions, exposed paths, and access rules |
| `build/nginx/config/options-ssl-nginx.conf` | TLS defaults |
| `build/nginx/web/` | static site content |
| `docker-compose.yml` | volume mounts, env vars, and health check |
| `VERSION` | stack release tag used by published images |

## Intentionally Vulnerable Behavior

- `/voicemail/` has fancy directory indexing enabled via the `fancyindex` module
- `/call/` serves the browser softphone over HTTPS so browsers can access the microphone; HTTP requests are redirected to HTTPS with a 301
- `/logs/useragents` exposes client-controlled data exported from MySQL
- `/secret/` is blocked externally (returns a custom `403.html` error page) but reachable on the loopback-only server block used in the TURN relay exercise
- the public landing page links to `/call/`, `/logs/`, and `/secret/`
- `/__version` returns the versioned-image metadata for the running nginx image

## Verification

```bash
. ./.env
curl "http://$PUBLIC_IPV4/"
curl -I "http://$PUBLIC_IPV4/voicemail/"
curl "http://$PUBLIC_IPV4/__version"
docker compose logs nginx
```

On a native Linux Docker host, `curl http://127.0.0.1/` is also a useful local-bind check. On Colima or another Linux VM workflow, use the bridged `PUBLIC_IPV4` from `.env` for host-side verification.

## Related Documentation

- [Overview](overview.md)
- [Architecture](architecture.md)
- [coturn Reference](coturn.md)
- [Support Services](support-services.md)
