# opengwtools

LZ Connectivity - deployment and configuration support for popular gateways.

## MikroTik bootstrap helper

Use `bootstrap_routeros.sh` to push the base RouterOS configuration (`02_routeros-7.18-base.rsc`) onto a freshly provisioned MikroTik that currently has a DHCP-assigned address.

1. Ensure you can SSH to the router (default user is `admin`).
2. Run `./bootstrap_routeros.sh` to open the MikroTik CHR Bootstrap Utility menu:
	- **Test SSH connection** shows the router identity using the stored credentials, defaulting to the DHCP IP so you can verify access before the static address is applied.
	- **Deploy** regenerates the `.rsc`, uploads it as `opengwtools-bootstrap`, verifies SSH on the new static bridge IP (after clearing any cached host key), leaves the script available on the router, and then lists the Winbox checks you should perform to confirm each configured setting.
	- **Edit configuration** guides you through updating the JSON settings with DHCP-aware defaults (the static gateway defaults to the last usable address, `.254` on /24 networks) and stores the results in `bootstrap_routeros.json`.
3. Re-run the helper any time you need to tweak the bootstrap configuration; the saved JSON persists your inputs between sessions.

After deployments, open `/log print follow` on the router to review the bootstrap activity that was logged by the script.
