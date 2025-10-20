# VPN Roadwarriors Utility

Interactive helper for managing a MikroTik WireGuard "roadwarrior" (remote user) VPN on top of the bootstrap configuration.

## Overview

`vpn_roadwarriors.py` provides a lightweight menu to keep a WireGuard server interface and its peers in sync between a MikroTik CHR and the local JSON cache. The VPN helper and the bootstrap/proxmox tooling in the repository are designed to run independently—only the shared configuration files tie them together.

1. **Test SSH connection to MikroTik** – Quickly validate credentials/IP before making changes. The stored router IP defaults to the static address from `bootstrap/bootstrap_routeros.json`, but any new value entered here will be saved back to `vpn-roadwarriors.json` for future runs.
2. **Check and create WireGuard Server** – Ensures the `opengwtools-roadwarriors` interface exists, generates server keys if missing, sets the listen port and interface address, and reconciles the local cache with peers found on the router.
3. **Add new WireGuard Peer** – Prompts for the user's name and an optional comment, creates a unique peer on the CHR (allocating the next free address in `10.255.0.0/24`), stores the keys in `vpn-roadwarriors.json`, and writes a ready-to-import WireGuard client configuration into `clients/`.
4. **Remove WireGuard Peer** – Lets you pick a cached peer, removes it from the MikroTik and deletes the corresponding client configuration file. The removal list is numbered so you can safely target the intended user, and the script confirms each deletion across the router, JSON, and local file system.
5. **List WireGuard Peers** – Displays the managed peers in a numbered table (this option appears once at least one peer exists).
6. **Exit** – Leaves the utility.

All peer records are written to `vpn-roadwarriors.json` alongside the server metadata so that rerunning the tool keeps state. The generated `.conf` files live under `vpn-roadwarriors/clients/` and are named using the pattern `<firstname>-<lastname>-<RANDOMID>.conf`, matching the peer identity stored on the router.

> **Quick checklist before each run**
>
> 1. Open `vpn-roadwarriors.json` and confirm the connection (SSH) and server values are current—especially `routerIp`, `routerPublicIp`, and the baseline allowed networks.
> 2. Verify passwordless SSH or test your credentials against the MikroTik CHR; the menu includes a dedicated option for this, but confirming ahead of time avoids failed provisioning runs.

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

### Importing on iPhone / iPad

The iOS WireGuard client exposes the `Allowed IPs` fields only when a configuration file is imported. Do **not** create tunnels from scratch inside the app—manual creation hides the advanced routing values and the tunnel will default to a single host route.

1. Email (or otherwise securely transfer) the generated `.conf` file to the user.
2. On the iPhone, open the message and tap the attachment, then choose **Copy to WireGuard** (or **Open in WireGuard**).
3. When the WireGuard app opens, pick **Create from file or archive** and select the downloaded configuration.
4. Review the imported tunnel details; the `Allowed IPs` section should already list the baseline networks defined in `vpn-roadwarriors.json`.
5. Tap **Save**, then toggle the switch to activate the VPN.

## Windows compatibility notes

The utility was originally authored on Ubuntu, but the current release includes several improvements to work smoothly on Windows as well:

- **Password-based SSH** – When `sshpass` is unavailable (default on Windows), the script falls back to Paramiko so you can enter the router password once and reuse the same session. Install it with `pip install paramiko`.
- **Handled ANSI colors** – The prompts now auto-detect consoles that don’t support ANSI escape sequences and disable color codes to avoid stray `←[90m` artifacts.
- **Plain-text command output** – SSH responses invoked through Paramiko are decoded and printed without the Python byte-string prefixes (no `b'…'` clutter), matching the Linux behavior.

With these adjustments the menu flow, WireGuard provisioning, and file generation behave the same on both Windows PowerShell and Linux shells.
