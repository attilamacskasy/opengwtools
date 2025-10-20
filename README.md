# opengwtools

LZ Connectivity - deployment and configuration support for popular gateways.

## Repository structure

- `bootstrap/` — RouterOS scripts used to bootstrap certificates, security, and base configuration for MikroTik gateways.
- `certs/` — Place exported CA or client certificates here for Terraform to consume (kept empty in git with `.gitkeep`).
- `docs/` — Architecture and design diagrams (`.drawio`) documenting gateway workflows.
- `proxmox/` — Utilities for spinning up MikroTik CHR test environments on Proxmox, including deployment scripts and guides.
- `vpn-roadwarriors/` — Standalone WireGuard peer management helper; can be run independently once the MikroTik CHR is reachable via SSH.

## Getting started

Each toolkit directory is self-contained. You can bootstrap a CHR, manage WireGuard peers, or experiment with Proxmox deployments independently—just make sure the configuration JSON files inside each tool reflect your environment before running them.

Before using any script that talks to the MikroTik CHR:

1. Open the relevant configuration JSON (for example, `vpn-roadwarriors/vpn-roadwarriors.json`) and verify the IP addresses, credentials, and other settings are current.
2. Confirm that SSH connectivity to the CHR succeeds (the VPN helper provides a menu option to test this directly).

