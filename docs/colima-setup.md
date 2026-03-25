# Colima Bridged Networking Setup on macOS

This guide sets up Colima with bridged networking so the VM gets a real IP on your current network, enabling `--network host` to work properly with Docker containers.
Direct Docker Desktop deployment on macOS is not the supported path for DVRTC because the stack depends on host networking semantics.

## Prerequisites

- macOS with Homebrew installed
- Docker CLI and Compose plugin installed (`brew install docker docker-compose`)
- Colima installed (`brew install colima`)

## Step 1: Configure Lima vmnet using the official docs

Follow Lima's official vmnet setup guide:

- <https://lima-vm.io/docs/config/network/vmnet/>

For DVRTC, use Lima's managed vmnet flow for bridged networking. That setup includes:

- installing `socket_vmnet` in a root-owned, non-symlink path
- configuring `~/.lima/_config/networks.yaml`
- installing the Lima sudoers entry
- creating `/private/var/run/lima`

Do not use a separate `brew services` `socket_vmnet` launchd service for this workflow. Lima starts the managed daemon automatically when a VM using that network starts.

## Step 2: Start Colima with bridged networking

If you have an existing Colima instance, delete it first (network mode can't be changed after creation):

```bash
colima stop
colima delete --force
```

Official Colima guidance keeps `shared` networking as the default and recommended mode. DVRTC is a repo-specific exception: use `bridged` here because the stack needs a VM address that is reachable as a real host on your LAN, so Docker `--network host` inside the VM behaves in a way that matches the documented DVRTC workflow.

Start Colima with bridged networking and enough resources for a full DVRTC stack:

```bash
colima start --network-address --network-mode bridged --vm-type vz --cpu 8 --memory 16 --disk 200
```

The default 2 CPU / 2 GB Colima allocation is too small for the full DVRTC stack. In practice, `--cpu 8 --memory 16 --disk 200` has been a more reliable DVRTC baseline for local builds, packet capture, and the full testing workflow. These values are not general Colima requirements; they are a tested starting point for this repository.

The command above does not pass `--mount-type virtiofs` because current Colima releases already default VZ instances to `virtiofs`.

On Apple Silicon, include `--vz-rosetta`:

```bash
colima start --network-address --network-mode bridged --vm-type vz --cpu 8 --memory 16 --disk 200 --vz-rosetta
```

Rosetta support is required for this setup to work reliably with DVRTC's `linux/amd64` image and build requirements on Apple Silicon.

If you prefer persistent config instead of passing CLI flags each time, run `colima start --edit` and set the same values in the profile. On Apple Silicon, make sure `rosetta: true` is set in `~/.colima/default/colima.yaml` before starting the VM.

### Changing resources on an existing instance

If you need to change the resource settings later, stop Colima and start it again with the updated values:

```bash
colima stop
colima start --cpu 8 --memory 16 --disk 200
```

Verify the current allocation:

```bash
colima list
```

## Step 3: Set the bridged IPs

The `setup_networking.sh` script auto-detects the Colima VM's bridged IPv4 and, when the VM has a usable global or ULA address, its IPv6 too:

```bash
./scripts/setup_networking.sh
```

To verify the IPs manually:

```bash
colima ssh -- ip addr show
colima ssh -- ip -6 addr show scope global
```

Look for the bridged interface that Colima created. It should have an IPv4 address on your LAN subnet (for example `192.168.x.x`). If your network provides IPv6, it should also have a usable global or ULA IPv6 address. If no usable IPv6 address is present, leave `PUBLIC_IPV6` unset and DVRTC stays IPv4-only.

## Optional: Add custom CA certificate

If you have a private registry with a custom CA:

```bash
cat /path/to/your-ca.crt | colima ssh -- sudo tee /usr/local/share/ca-certificates/your-ca.crt > /dev/null
colima ssh -- sudo update-ca-certificates
```

## Usage

Once Colima is up with bridged networking, use the normal DVRTC setup flow from your host shell:

```bash
./scripts/setup_networking.sh
./scripts/generate_passwords.sh
./scripts/init-selfsigned.sh
./scripts/validate_env.sh
docker compose up -d
docker compose ps
```

For host-side access checks from macOS, use the bridged `PUBLIC_IPV4` written to `.env`, not `127.0.0.1`:

```bash
. ./.env
curl "http://${PUBLIC_IPV4}/"
```

If you want to test loopback inside the Colima VM itself, use:

```bash
colima ssh -- curl http://127.0.0.1/
```

If you rebuild images locally on Apple Silicon, follow [development.md](development.md) and keep the `linux/amd64` build requirement in mind.

## Notes

- The bridged IP is assigned via DHCP, so it may change across restarts
- IPv6 availability depends on your LAN/router. Bridged Colima does not invent IPv6; it can only use an address actually assigned to the VM
- Bridged means the VM is directly on your current network; if that network is private/NAT'd, inbound access from the public internet still requires port forwarding or a public IP
- The CA certificate and other VM customizations won't survive `colima delete` - you'll need to re-add them
- Consider setting a static DHCP lease on your router for a consistent IP
