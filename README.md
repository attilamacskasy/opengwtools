# opengwtools

LZ Connectivity - deployment and configuration support for popular gateways.

## Repository structure

- `bootstrap/` — RouterOS scripts used to bootstrap certificates, security, and base configuration for MikroTik gateways.
- `certs/` — Place exported CA or client certificates here for Terraform to consume (kept empty in git with `.gitkeep`).
- `docs/` — Architecture and design diagrams (`.drawio`) documenting gateway workflows.
- `proxmox/` — Utilities for spinning up MikroTik CHR test environments on Proxmox, including deployment scripts and guides.

## Getting started

