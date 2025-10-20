# VPN Roadwarriors Utility

Interactive helper for managing a MikroTik WireGuard "roadwarrior" (remote user) VPN on top of the bootstrap configuration.

## Overview

`vpn_roadwarriors.py` provides a lightweight menu to keep a WireGuard server interface and its peers in sync between a MikroTik CHR and the local JSON cache:

1. **Test SSH connection to MikroTik** – Quickly validate credentials/IP before making changes. The stored router IP defaults to the static address from `bootstrap/bootstrap_routeros.json`, but any new value entered here will be saved back to `vpn-roadwarriors.json` for future runs.
2. **Check and create WireGuard Server** – Ensures the `opengwtools-roadwarriors` interface exists, generates server keys if missing, sets the listen port and interface address, and reconciles the local cache with peers found on the router.
3. **Add new WireGuard Peer** – Prompts for the user's name and an optional comment, creates a unique peer on the CHR (allocating the next free address in `10.255.0.0/24`), stores the keys in `vpn-roadwarriors.json`, and writes a ready-to-import WireGuard client configuration into `clients/`.
4. **Remove WireGuard Peer** – Lets you pick a cached peer, removes it from the MikroTik and deletes the corresponding client configuration file.
5. **Exit** – Leaves the utility.

All peer records are written to `vpn-roadwarriors.json` alongside the server metadata so that rerunning the tool keeps state. The generated `.conf` files live under `vpn-roadwarriors/clients/` and are named using the pattern `<firstname>-<lastname>-<RANDOMID>.conf`, matching the peer identity stored on the router.

### Allowed IP defaults

You can control which networks the client routes through the tunnel by editing `server.baselineAllowedIps` in `vpn-roadwarriors.json`. By default it includes `0.0.0.0/0` and `::/0` (full tunnel). Provide any combination of CIDRs and the tool will:

- Append them to each client's `AllowedIPs` line in the generated config
- Add the same list to the peer's `allowed-address` on the MikroTik (alongside the tunnel /32)

## Requirements

- Python 3.8+
- `ssh` available in PATH
- Optional: `sshpass` for password-based logins (you will be prompted when needed)
- WireGuard key generation support on the workstation:
	- Recommended: Python package `cryptography` (provides X25519 key generation), or
	- Alternative: the `wg` CLI from the WireGuard tools package

## Usage

```bash
cd vpn-roadwarriors
./vpn_roadwarriors.py
```

If the script is not executable, run `python3 vpn_roadwarriors.py` instead. The utility stores all updates immediately, so you can safely rerun it to continue provisioning users.

## Distributing Client Configurations

After adding a peer, copy the generated `.conf` file to the end user. In the WireGuard desktop app for Windows:

1. Click **Import tunnel(s) from file...**
2. Select the provided configuration (the tunnel name will match the file name)
3. Click **Activate** to establish the VPN connection

The configuration includes a full-tunnel (`0.0.0.0/0`) policy and a persistent keepalive value of 25 seconds; adjust these defaults in the script if your deployment requires different behavior.
