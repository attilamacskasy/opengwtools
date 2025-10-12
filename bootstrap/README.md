# opengwtools

LZ Connectivity - deployment and configuration support for popular gateways.

## MikroTik bootstrap helper

Use `bootstrap_routeros.sh` to push the base RouterOS configuration (`02_routeros-7.18-base.rsc`) onto a freshly provisioned MikroTik that currently has a DHCP-assigned address.

1. Ensure you can SSH to the router (default user is `admin`). The script prompts for the temporary DHCP IP before switching to the static bridge IP.
2. Run `./bootstrap_routeros.sh` from this directory. It will:
	- Pre-populate `bootstrap_routeros.json` with globals extracted from the base script.
	- Prompt for each global value, deriving sensible defaults from the temporary DHCP IP (static gateway defaults to the last usable address, `.254` on /24 networks).
	- Optionally disable the MikroTik DHCP server to avoid conflicts with an existing upstream DHCP.
	- Confirm the current router identity before making changes so you know connectivity is working.
	- Regenerate the `.rsc`, upload it to the router as `opengwtools-bootstrap`, execute it, and verify SSH connectivity on the new static IP.
	- Persist the script on the router, so you can re-run it manually later if needed.
3. Re-run the helper any time you need to tweak the bootstrap configuration; edits are stored in `bootstrap_routeros.json` for reuse.

After the run completes, open `/log print follow` on the router to review the bootstrap activity that was logged by the script.
