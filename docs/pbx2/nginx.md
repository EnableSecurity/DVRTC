# Nginx Reference

## Role In Scenario

Nginx provides the HTTP and HTTPS surface for `pbx2`. It serves the scenario landing page, exposes the shared RTP recordings volume, and publishes version metadata for the running image.

- ports: `80/TCP` and `443/TCP`
- network mode: host
- certificates are read from `data/certs`
- the shared `rtp-recordings` and `acme-challenge` volumes are mounted into the document root
- the running image exposes release metadata at `/__version`
- the default `pbx2` web content is a scenario landing page with the recordings link, the standard DVRTC warning, and a GitHub link to the documentation and exercises

## Key Files

| File | Purpose |
|------|---------|
| `build/nginx/config/sites-available/default.pbx2` | site definition, exposed paths, and recording index |
| `build/nginx/config/options-ssl-nginx.conf` | TLS defaults |
| `build/nginx/web-pbx2/` | static site content for the `pbx2` landing page |
| `build/nginx/run.sh` | scenario-aware content/config selection and reload loop |
| `compose/pbx2.yml` | volume mounts, env vars, and health check |
| `VERSION` | stack release tag used by published images |

## Current Web Surface

- `/recordings/` has fancy directory indexing enabled via the `fancyindex` module
- the pbx2 landing page and recordings directory stylesheet follow the browser/system light or dark color preference with CSS `prefers-color-scheme`
- the active recording spool is reachable below `/recordings/spool/`
- both HTTP and HTTPS expose the same recordings surface
- the landing page links directly to the recording index and to the DVRTC GitHub documentation
- `/__version` reveals the versioned-image metadata for the running nginx image

## Scenario-Specific Notes

### SIP/TLS Handling

OpenSIPS listens on `5061/TCP` directly when certificates exist under `data/certs`.

## Verification

```bash
. ./.env
curl "http://$PUBLIC_IPV4/"
curl -I "http://$PUBLIC_IPV4/recordings/"
curl "http://$PUBLIC_IPV4/__version"
./scripts/compose.sh --scenario pbx2 logs nginx-pbx2
```

On a native Linux Docker host, `curl http://127.0.0.1/` is also a useful local-bind check. On Colima or another Linux VM workflow, prefer the bridged `PUBLIC_IPV4` from `.env` for host-side verification because it matches the VM's real service identity.

## Related Documentation

- [Overview](overview.md)
- [Architecture](architecture.md)
- [RTPProxy Reference](rtpproxy.md)
- [Support Services](support-services.md)
