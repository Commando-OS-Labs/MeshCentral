# Commando360 managed support overlay

This directory keeps Commando-specific integration outside MeshCentral's transport and security core. The upstream repository remains mergeable.

## Architecture

- MeshCentral: agent connectivity and browser remote-control transport.
- Broker: converts one Commando Gateway Support approval into three independent, device-specific guest shares: desktop, terminal and files.
- Commando Platform: authentication, Super Admin authorization, local consent, expiry, operator audit and revocation.
- Caddy: public TLS for agent transport and the broker. The operator console is available only through Tailscale Serve on port 8443. MongoDB and both application containers remain private.

No MeshCentral administrator credential, login token or device inventory is returned to Commando Platform or a browser.

## VPS baseline

- Ubuntu 24.04 LTS; 2 vCPU; 4 GB RAM; 40–60 GB encrypted SSD.
- Three DNS records pointing to the VPS: the active agent host, a reserved dedicated agent host and a broker host. Both public support hosts are agent-only; the established host remains the enrollment alias until all Gateways can migrate without changing certificate identity.
- Only TCP 22, 80 and 443 exposed. SSH restricted to approved administrator addresses.
- A deny-by-default Tailscale grants policy allowing approved support identities to reach only the VPS console on TCP 8443. Support users remain ordinary members and receive no access to other tailnet devices.
- Daily encrypted volume snapshot plus the MeshCentral backup volume copied off-host.

## Bootstrap inputs

1. Copy `commando/deploy/.env.example` to `.env` and provide the three public hosts, private Tailscale console origin, ACME email, Platform framing origins and MongoDB credentials.
2. Create `commando/deploy/secrets/broker-token` and `mesh-session-key` with at least 64 random characters. Keep the parent `secrets` directory at `0700`; use `0444` for these bind-mounted files so the non-root broker can read only the secrets explicitly mounted into its container.
3. Create a least-privilege `commando-broker` MeshCentral account with remote-control and guest-sharing rights only for the managed Gateway device group. Retain the restrictive `--noamt --limitedevents --noregistry --nosoftware` flags and do not grant group administration, device management, uninstall, server-file or agent-console rights. Store its long random password in `secrets/mesh-login-password`; use the same protected-directory permissions described above.
4. Copy `devices.example.json` to `devices.json`. Add only commissioned company-owned devices and bind every MeshCentral node ID to both Gateway ID and current device-key ID. Keep this non-secret allowlist at `0444`: the broker runs as a non-root user and receives it through a read-only mount.
5. Run `docker compose --env-file .env -f commando/deploy/compose.yaml config`, then `docker compose --env-file .env -f commando/deploy/compose.yaml up -d --build`.
6. Run `tailscale serve --bg --https=8443 http://127.0.0.1:18080` on the host. Confirm the private URL works from an approved tailnet device and both public support hosts reject UI requests.
7. Configure Platform with the broker URL, private console origin and the same broker token. Never put MeshCentral credentials in Platform.

For the shared Vultr inference host, also pass
`-f commando/deploy/compose.vultr.yaml`. This keeps port 80 assigned to the
existing inference proxy and caps the managed-support stack at 1.25 vCPU and
1.25 GB RAM. Set `SUPPORT_BIND_IP` to the VPS public IPv4 address so a private
Tailscale listener can retain its own port 443. Treat this as a low-concurrency
POC profile, not a scale target.

Production rollout requires restore testing, expiry and revocation drills, agent-signing verification and a representative Windows and Linux qualification.
