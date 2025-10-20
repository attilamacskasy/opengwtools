#!/usr/bin/env python3
"""Interactive WireGuard road-warrior helper for MikroTik CHR."""

from __future__ import annotations

import base64
import datetime
import getpass
import ipaddress
import json
import os
import random
import re
import shutil
import subprocess
import sys
import textwrap

try:
    import paramiko  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    paramiko = None  # type: ignore

COLOR_CMD = "\033[90m"  # dark gray
COLOR_RESET = "\033[0m"

from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = SCRIPT_DIR / "vpn-roadwarriors.json"
CLIENTS_DIR = SCRIPT_DIR / "clients"
BOOTSTRAP_CONFIG = SCRIPT_DIR.parent / "bootstrap" / "bootstrap_routeros.json"
DEFAULT_ROUTER_IP = "172.22.254.254"
DEFAULT_INTERFACE_NAME = "opengwtools-roadwarriors"
DEFAULT_LISTEN_PORT = 51820
DEFAULT_SERVER_ADDRESS = "10.255.0.1/24"
DEFAULT_PEER_NETWORK = "10.255.0.0/24"
DEFAULT_DNS = "10.255.0.1"
HEADER_BAR = "=" * 45
HEADER_TITLE = "=== MikroTik CHR VPN Roadwarriors Utility ==="
TAGLINE = "Creative spark and vibe AI coding with continuous debugging and improvements by: Attila Macskasy"
MODEL_LINE = "Code generated using: GPT-5 Codex (Preview) — Premium Model x1"


def _supports_ansi_colors() -> bool:
    if not sys.stdout.isatty():  # pragma: no cover - environment dependent
        return False
    if os.name != "nt":
        return True
    return bool(
        os.environ.get("ANSICON")
        or os.environ.get("WT_SESSION")
        or os.environ.get("TERM_PROGRAM") == "vscode"
        or os.environ.get("TERM", "").startswith("xterm")
    )


if not _supports_ansi_colors():
    COLOR_CMD = ""
    COLOR_RESET = ""


def build_menu(config: Dict[str, Any]) -> Tuple[str, Set[str]]:
    peers = config.get("peers", [])
    peer_count = len(peers)
    lines = [
        f"Currently configured WireGuard Peers: {peer_count}",
        "",
        "Menu:",
        "",
        "    1) Test SSH connection to MikroTik",
        "    2) Check and create WireGuard Server",
        "    3) Add new WireGuard Peer",
        "    4) Remove WireGuard Peer",
    ]
    valid_choices: Set[str] = {"1", "2", "3", "4", "6"}
    if peer_count > 0:
        lines.append("    5) List WireGuard Peers")
        valid_choices.add("5")
    lines.append("    6) Exit")
    menu_text = "\n".join(lines) + "\n"
    return menu_text, valid_choices


def _mask_sensitive_value(key: str, value: Any) -> str:
    if isinstance(value, str):
        if "key" in key.lower():
            if len(value) <= 6:
                return (value[:1] + "***") if value else "***"
            return f"{value[:3]}***{value[-3:]}"
        return value
    if isinstance(value, list):
        return ", ".join(
            _mask_sensitive_value(key, item) if isinstance(item, str) else str(item) for item in value
        )
    if isinstance(value, dict):
        return json.dumps(value)
    return str(value)


def print_config_summary(config: Dict[str, Any]) -> None:
    print(HEADER_BAR)
    print(HEADER_TITLE)
    print(HEADER_BAR)
    print(f"Configuration loaded from file: {CONFIG_PATH.name}\n")

    connection = config.get("connection", {})
    server = config.get("server", {})

    print("[vpn-roadwarriors] Connection settings:")
    for key, value in connection.items():
        print(f"  {key}: {_mask_sensitive_value(key, value)}")
    print()
    print("[vpn-roadwarriors] Server settings:")
    for key, value in server.items():
        print(f"  {key}: {_mask_sensitive_value(key, value)}")
    print()


class SSHClient:
    """Thin wrapper around ssh/sshpass with optional password caching."""

    def __init__(self, user: str, host: str, port: int) -> None:
        self.user = user
        self.host = host
        self.port = port
        self.password: Optional[str] = None
        self.sshpass_path = shutil.which("sshpass")

    def matches(self, user: str, host: str, port: int) -> bool:
        return self.user == user and self.host == host and self.port == port

    def run(self, command: str, *, allow_password: bool = True, check: bool = True) -> subprocess.CompletedProcess[str]:
        print(f"{COLOR_CMD}[vpn-roadwarriors] -> {command}{COLOR_RESET}")
        base_cmd = [
            "ssh",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=10",
            "-p",
            str(self.port),
            f"{self.user}@{self.host}",
            command,
        ]
        result = subprocess.run(base_cmd, capture_output=True, text=True)

        if result.returncode == 255 and allow_password:
            if self.password is None:
                try:
                    self.password = getpass.getpass(
                        f"[vpn-roadwarriors] Router password for {self.user}@{self.host}: "
                    )
                except (EOFError, KeyboardInterrupt):
                    print("\n[vpn-roadwarriors] Password prompt cancelled.")
                    raise

            if self.sshpass_path:
                env = os.environ.copy()
                env["SSHPASS"] = self.password or ""
                pass_cmd = [
                    self.sshpass_path,
                    "-e",
                    "ssh",
                    "-T",
                    "-o",
                    "StrictHostKeyChecking=accept-new",
                    "-o",
                    "ConnectTimeout=10",
                    "-p",
                    str(self.port),
                    f"{self.user}@{self.host}",
                    command,
                ]
                result = subprocess.run(pass_cmd, capture_output=True, text=True, env=env)
            elif paramiko is not None:
                result = self._run_with_paramiko(command, base_cmd)
            else:
                print(
                    "[vpn-roadwarriors] Password authentication failed and sshpass/paramiko are unavailable. "
                    "Install paramiko (`pip install paramiko`) or configure key-based SSH access."
                )

        if result.stdout:
            print(f"{COLOR_CMD}[vpn-roadwarriors] <- stdout:{COLOR_RESET}")
            print(f"{COLOR_CMD}{result.stdout.strip()}{COLOR_RESET}")
        if result.stderr:
            print(f"{COLOR_CMD}[vpn-roadwarriors] <- stderr:{COLOR_RESET}")
            print(f"{COLOR_CMD}{result.stderr.strip()}{COLOR_RESET}")

        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode,
                " ".join(base_cmd),
                output=result.stdout,
                stderr=result.stderr,
            )
        return result

    def _run_with_paramiko(
        self, command: str, base_cmd: List[str]
    ) -> subprocess.CompletedProcess[str]:
        if paramiko is None:  # pragma: no cover
            raise RuntimeError("Paramiko is not available.")

        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(
            hostname=self.host,
            port=self.port,
            username=self.user,
            password=self.password,
            look_for_keys=False,
            allow_agent=False,
            timeout=10,
        )

        transport = ssh_client.get_transport()
        if transport is None:
            ssh_client.close()
            raise RuntimeError("Failed to establish SSH transport.")

        channel = transport.open_session()
        channel.exec_command(command)
        stdout_file = channel.makefile("rb", -1)
        stderr_file = channel.makefile_stderr("rb", -1)
        stdout_bytes = stdout_file.read()
        stderr_bytes = stderr_file.read()
        stdout_file.close()
        stderr_file.close()
        exit_status = channel.recv_exit_status()
        channel.close()
        ssh_client.close()

        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        stderr_text = stderr_bytes.decode("utf-8", errors="replace")

        return subprocess.CompletedProcess(base_cmd, exit_status, stdout_text, stderr_text)


def ensure_config_exists() -> None:
    if CONFIG_PATH.exists():
        return

    default_ip = DEFAULT_ROUTER_IP
    if BOOTSTRAP_CONFIG.exists():
        try:
            with BOOTSTRAP_CONFIG.open(encoding="utf-8") as fh:
                bootstrap = json.load(fh)
            connection = bootstrap.get("connection", {})
            globals_section = bootstrap.get("globals", {})
            for candidate in (
                connection.get("staticIp"),
                connection.get("dhcpIp"),
                globals_section.get("bridgeIP"),
            ):
                if candidate:
                    default_ip = str(candidate)
                    break
        except (json.JSONDecodeError, OSError):
            pass

    config: Dict[str, Any] = {
        "connection": {
            "sshUser": "admin",
            "sshPort": 22,
            "routerIp": default_ip,
            "routerPublicIp": default_ip,
        },
        "server": {
            "interfaceName": DEFAULT_INTERFACE_NAME,
            "listenPort": DEFAULT_LISTEN_PORT,
            "address": DEFAULT_SERVER_ADDRESS,
            "peerNetworkCidr": DEFAULT_PEER_NETWORK,
            "dns": DEFAULT_DNS,
            "publicKey": "",
            "privateKey": "",
            "baselineAllowedIps": ["0.0.0.0/0", "::/0"],
        },
        "peers": [],
    }

    CONFIG_PATH.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    CLIENTS_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> Dict[str, Any]:
    ensure_config_exists()
    with CONFIG_PATH.open(encoding="utf-8") as fh:
        data = json.load(fh)
    data.setdefault("connection", {})
    data.setdefault("server", {})
    data.setdefault("peers", [])

    conn = data["connection"]
    conn.setdefault("sshUser", "admin")
    conn.setdefault("sshPort", 22)
    conn.setdefault("routerIp", DEFAULT_ROUTER_IP)
    conn.setdefault("routerPublicIp", conn.get("routerIp", DEFAULT_ROUTER_IP))
    conn["sshPort"] = int(conn.get("sshPort", 22))

    server = data["server"]
    server.setdefault("interfaceName", DEFAULT_INTERFACE_NAME)
    server.setdefault("listenPort", DEFAULT_LISTEN_PORT)
    server.setdefault("address", DEFAULT_SERVER_ADDRESS)
    server.setdefault("peerNetworkCidr", DEFAULT_PEER_NETWORK)
    server.setdefault("dns", DEFAULT_DNS)
    server.setdefault("publicKey", "")
    server.setdefault("privateKey", "")
    server.setdefault("baselineAllowedIps", ["0.0.0.0/0", "::/0"])
    server["listenPort"] = int(server.get("listenPort", DEFAULT_LISTEN_PORT))
    baseline_allowed = server.get("baselineAllowedIps", [])
    if isinstance(baseline_allowed, str):
        baseline_allowed = [baseline_allowed]
    server["baselineAllowedIps"] = [str(item).strip() for item in baseline_allowed if str(item).strip()]

    # Normalize peers list
    normalized_peers: List[Dict[str, Any]] = []
    for peer in data.get("peers", []):
        if not isinstance(peer, dict):
            continue
        peer.setdefault("id", "")
        peer.setdefault("firstName", "")
        peer.setdefault("lastName", "")
        peer.setdefault("comment", "")
        peer.setdefault("publicKey", "")
        peer.setdefault("privateKey", "")
        peer.setdefault("allowedAddress", "")
        peer.setdefault("configFile", "")
        peer.setdefault("presharedKey", "")
        peer.setdefault("allowedIps", [])
        peer.setdefault("routerAllowed", [])
        normalized_peers.append(peer)
    data["peers"] = normalized_peers
    return data


def save_config(data: Dict[str, Any]) -> None:
    CLIENTS_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def ensure_ssh_client(data: Dict[str, Any], existing: Optional[SSHClient]) -> SSHClient:
    conn = data["connection"]
    user = conn["sshUser"]
    host = conn["routerIp"]
    port = int(conn["sshPort"])
    if existing and existing.matches(user, host, port):
        return existing
    return SSHClient(user=user, host=host, port=port)


def validate_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


def prompt_ipv4(label: str, default: str) -> str:
    while True:
        raw = input(f"{label} [{default}]: ").strip()
        if not raw:
            raw = default
        if validate_ipv4(raw):
            return raw
        print("[vpn-roadwarriors] Invalid IPv4 address. Please try again.")


def prompt_nonempty(label: str) -> str:
    while True:
        raw = input(f"{label}: ").strip()
        if raw:
            return raw
        print("[vpn-roadwarriors] Value cannot be empty.")


def prompt_optional(label: str) -> str:
    return input(f"{label} (optional): ").strip()


def parse_property_tokens(blob: str) -> Dict[str, str]:
    tokens = {}
    for match in re.finditer(r"([A-Za-z0-9\-]+)=('([^']*)'|\"([^\"]*)\"|(\S+))", blob):
        key = match.group(1)
        value = match.group(3) or match.group(4) or match.group(5) or ""
        tokens[key] = value
    return tokens


def parse_peer_entries(blob: str) -> List[Dict[str, str]]:
    entries: List[Dict[str, str]] = []
    current_lines: List[str] = []
    for line in blob.splitlines():
        stripped = line.strip()
        if not stripped:
            if current_lines:
                entries.append(" ".join(current_lines))
                current_lines = []
            continue
        if stripped.startswith("Flags:"):
            continue
        current_lines.append(stripped)
    if current_lines:
        entries.append(" ".join(current_lines))
    return [parse_property_tokens(entry) for entry in entries if entry]


def parse_key_value_lines(blob: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for line in blob.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def compute_next_allowed_address(config: Dict[str, Any], extra_used: Optional[List[str]] = None) -> str:
    server = config["server"]
    network = ipaddress.ip_network(server.get("peerNetworkCidr", DEFAULT_PEER_NETWORK), strict=False)
    server_ip = ipaddress.ip_interface(server.get("address", DEFAULT_SERVER_ADDRESS)).ip
    used = {server_ip}
    if extra_used:
        for addr in extra_used:
            try:
                used.add(ipaddress.ip_interface(addr).ip)
            except ValueError:
                continue
    for peer in config.get("peers", []):
        allowed = peer.get("allowedAddress")
        if not allowed:
            continue
        try:
            peer_ip = ipaddress.ip_interface(allowed).ip
            used.add(peer_ip)
        except ValueError:
            continue
    for candidate in network.hosts():
        if candidate not in used:
            return f"{candidate}/32"
    raise RuntimeError("Address pool exhausted.")


def slugify(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", value.strip().lower())
    cleaned = cleaned.strip("-")
    return cleaned or "user"


def generate_peer_name(first: str, last: str, peers: List[Dict[str, Any]]) -> str:
    base_first = slugify(first)
    base_last = slugify(last)
    existing = {peer.get("id", "") for peer in peers}
    while True:
        suffix = f"{random.randint(0, 9999):04d}"
        name = f"{base_first}-{base_last}-{suffix}"
        if name not in existing:
            return name


def render_client_config(
    *,
    client_private: str,
    client_address: str,
    dns: str,
    peer_name: str,
    server_public: str,
    router_ip: str,
    listen_port: int,
    preshared_key: str = "",
    allowed_ips: Optional[List[str]] = None,
    keepalive: Optional[int] = 25,
) -> str:
    interface_block = ["[Interface]", f"PrivateKey = {client_private}", f"Address = {client_address}"]
    if dns:
        interface_block.append(f"DNS = {dns}")

    peer_block = [
        "[Peer]",
        f"PublicKey = {server_public}",
        f"AllowedIPs = {', '.join(allowed_ips) if allowed_ips else '0.0.0.0/0, ::/0'}",
        f"Endpoint = {router_ip}:{listen_port}",
    ]
    if preshared_key:
        peer_block.insert(2, f"PresharedKey = {preshared_key}")
    if keepalive:
        peer_block.append(f"PersistentKeepalive = {keepalive}")

    content = "\n".join(interface_block + ["", *peer_block])
    return content + "\n"


def write_client_config_file(peer_name: str, content: str) -> Path:
    CLIENTS_DIR.mkdir(parents=True, exist_ok=True)
    file_path = CLIENTS_DIR / f"{peer_name}.conf"
    file_path.write_text(content, encoding="utf-8")
    try:
        os.chmod(file_path, 0o600)
    except PermissionError:
        pass
    return file_path


def cleanup_missing_remote_peers(
    config: Dict[str, Any],
    remote_peers: List[Dict[str, str]],
) -> List[str]:
    remote_keys = {peer.get("public-key", "") for peer in remote_peers if peer.get("public-key")}
    removed_files: List[str] = []
    retained: List[Dict[str, Any]] = []
    for peer in config.get("peers", []):
        public_key = peer.get("publicKey")
        if public_key and public_key in remote_keys:
            retained.append(peer)
            continue
        if public_key:
            msg = f"[vpn-roadwarriors] Detected peer {peer.get('id')} missing from router; removing from local cache."
            print(msg)
        config_path = peer.get("configFile")
        if config_path:
            try:
                Path(config_path).unlink(missing_ok=True)  # type: ignore[arg-type]
            except OSError:
                pass
            else:
                removed_files.append(config_path)
    config["peers"] = retained
    return removed_files


def warn_untracked_remote_peers(remote_peers: List[Dict[str, str]], config: Dict[str, Any]) -> None:
    local_keys = {peer.get("publicKey") for peer in config.get("peers", []) if peer.get("publicKey")}
    warnings = []
    for peer in remote_peers:
        public_key = peer.get("public-key")
        if public_key and public_key not in local_keys:
            comment = peer.get("comment", "(no comment)")
            allowed = peer.get("allowed-address", "(no allowed address)")
            warnings.append(f"  - public-key {public_key} (comment: {comment}, allowed: {allowed})")
    if warnings:
        print("[vpn-roadwarriors] Warning: router has peers not tracked locally. Private keys for these peers are unknown to the tool:")
        for line in warnings:
            print(line)


def generate_key_pair() -> Tuple[str, str]:
    """Create a WireGuard key pair (private, public) in base64 form."""

    try:
        from cryptography.hazmat.primitives.asymmetric import x25519  # type: ignore
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption
        from cryptography.hazmat.primitives.serialization import PrivateFormat, PublicFormat

        priv_obj = x25519.X25519PrivateKey.generate()
        pub_obj = priv_obj.public_key()
        priv_bytes = priv_obj.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub_bytes = pub_obj.public_bytes(Encoding.Raw, PublicFormat.Raw)
        priv_key = base64.b64encode(priv_bytes).decode("ascii")
        pub_key = base64.b64encode(pub_bytes).decode("ascii")
        return priv_key, pub_key
    except Exception:
        pass

    wg_path = shutil.which("wg")
    if wg_path:
        private = subprocess.run([wg_path, "genkey"], check=True, capture_output=True, text=True).stdout.strip()
        public = subprocess.run([wg_path, "pubkey"], input=f"{private}\n", check=True, capture_output=True, text=True).stdout.strip()
        return private, public

    raise RuntimeError(
        "Unable to generate WireGuard key pair. Install the Python 'cryptography' package or the 'wg' CLI tool."
    )


def test_ssh_connection(config: Dict[str, Any], client: SSHClient) -> None:
    router_ip = prompt_ipv4("Router IP to test", config["connection"]["routerIp"])
    if router_ip != config["connection"]["routerIp"]:
        config["connection"]["routerIp"] = router_ip
        save_config(config)
        client.host = router_ip
        client.password = None

    try:
        result = client.run("/system identity print")
        output = result.stdout.strip()
        if not output:
            print("[vpn-roadwarriors] SSH connection succeeded (no output).")
        else:
            print(output)
    except subprocess.CalledProcessError as exc:
        print("[vpn-roadwarriors] SSH connection failed:")
        print(exc.stderr.strip() or exc.stdout.strip())


def ensure_wireguard_server(config: Dict[str, Any], client: SSHClient, *, verbose: bool = True) -> Tuple[Dict[str, Any], Dict[str, str], List[Dict[str, str]]]:
    server = config["server"]
    iface = server["interfaceName"]
    listen_port = int(server["listenPort"])
    address = server["address"]

    status_cmd = f'/interface/wireguard print where name={iface}'
    result = client.run(status_cmd, check=False)
    props = parse_property_tokens(result.stdout)

    if not props:
        if verbose:
            print(f"[vpn-roadwarriors] WireGuard interface {iface} not found. Creating...")
        try:
            priv_key, pub_key = generate_key_pair()
        except RuntimeError as exc:
            print(f"[vpn-roadwarriors] {exc}")
            return config, {}, []

        server["privateKey"] = priv_key
        server["publicKey"] = pub_key
        save_config(config)

        if verbose:
            print("[vpn-roadwarriors] Generated server key pair locally.")

        add_cmd = (
            f'/interface/wireguard add name="{iface}" listen-port={listen_port} '
            f'private-key="{priv_key}" comment="opengwtools-roadwarriors"'
        )
        add_result = client.run(add_cmd, check=False)
        if add_result.returncode != 0:
            print("[vpn-roadwarriors] Router returned an error while creating the interface; see output above.")
            return config, {}, []

        result = client.run(status_cmd, check=False)
        props = parse_property_tokens(result.stdout)

        firewall_rules = [
            f'/ip firewall filter add action=accept chain=input comment="allow input {iface} WAN" dst-port={listen_port} in-interface-list=WAN protocol=udp place-before=1',
            f'/ip firewall filter add action=accept chain=input comment="allow input {iface} LAN" dst-port={listen_port} in-interface-list=LAN protocol=udp place-before=1',
            f'/ip firewall filter add action=accept chain=forward comment="allow forward {iface}" in-interface={iface} place-before=2',
        ]
        for rule in firewall_rules:
            client.run(rule, check=False)
    else:
        if verbose:
            print(f"[vpn-roadwarriors] WireGuard interface {iface} already present.")

    if props:
        current_port = props.get("listen-port")
        if current_port and int(current_port) != listen_port:
            adjust_cmd = f'/interface/wireguard set [find where name="{iface}"] listen-port={listen_port}'
            client.run(adjust_cmd)
            if verbose:
                print(f"[vpn-roadwarriors] Updated listen-port to {listen_port}.")
        if "public-key" in props and props.get("public-key"):
            server["publicKey"] = props.get("public-key")
        if "private-key" in props and props.get("private-key") and props.get("private-key") != "***":
            server["privateKey"] = props.get("private-key")
        save_config(config)

    if verbose:
        print(
            f"[vpn-roadwarriors] Interface {iface} listening on {address} (port {listen_port}), public key {server.get('publicKey', '(unknown)')}"
        )

    ensure_address_script = (
        f':local addr "{address}"; '
        f'/ip address {{ :local existing [find where interface="{iface}" && address=$addr]; '
        f':if ([:len $existing] = 0) do={{ add address=$addr interface="{iface}" comment="opengwtools-roadwarriors"; }} }}; '
        ':put "status=address-ensured";'
    )
    address_result = client.run(ensure_address_script, check=False)
    address_status = parse_key_value_lines(address_result.stdout).get("status")
    if address_status != "address-ensured":
        print("[vpn-roadwarriors] Warning: Router did not confirm bridge address assignment.")

    peers_cmd = f'/interface/wireguard peers print detail where interface={iface}'
    peers_result = client.run(peers_cmd, check=False)
    remote_peers = parse_peer_entries(peers_result.stdout)

    removed_files = cleanup_missing_remote_peers(config, remote_peers)
    if removed_files and verbose:
        print("[vpn-roadwarriors] Removed stale peer configs:")
        for path in removed_files:
            print(f"  - {path}")

    warn_untracked_remote_peers(remote_peers, config)
    save_config(config)
    return config, props, remote_peers


def add_wireguard_peer(config: Dict[str, Any], client: SSHClient) -> None:
    config, props, remote_peers = ensure_wireguard_server(config, client, verbose=False)
    server = config["server"]
    server_public = server.get("publicKey") or props.get("public-key")
    if not server_public:
        print("[vpn-roadwarriors] Unable to determine server public key. Run option 2 first.")
        return

    first_name = prompt_nonempty("Peer first name")
    last_name = prompt_nonempty("Peer last name")
    comment = prompt_optional("Peer comment/description")
    peer_name = generate_peer_name(first_name, last_name, config.get("peers", []))

    remote_used = [peer.get("allowed-address") for peer in remote_peers if peer.get("allowed-address")]

    try:
        allowed_address = compute_next_allowed_address(config, remote_used)
    except RuntimeError as exc:
        print(f"[vpn-roadwarriors] {exc}")
        return

    try:
        client_private, client_public = generate_key_pair()
    except RuntimeError as exc:
        print(f"[vpn-roadwarriors] {exc}")
        return

    print("[vpn-roadwarriors] Generated client key pair locally.")

    cleaned_comment = comment.replace("\"", "'")
    baseline_allowed = server.get("baselineAllowedIps", [])
    if not baseline_allowed:
        baseline_allowed = ["0.0.0.0/0", "::/0"]
    allowed_ips = []
    for item in baseline_allowed:
        candidate = str(item).strip()
        if candidate and candidate not in allowed_ips:
            allowed_ips.append(candidate)

    router_allowed = [allowed_address]
    for item in allowed_ips:
        if item not in router_allowed:
            router_allowed.append(item)
    router_allowed_str = ",".join(router_allowed)

    iface = server["interfaceName"]
    add_script = (
        f'/interface/wireguard peers add name="{peer_name}" interface="{iface}" '
        f'public-key="{client_public}" allowed-address="{router_allowed_str}" comment="{cleaned_comment}"; '
        ':put "status=added";'
    )
    add_result = client.run(add_script, check=False)
    status = parse_key_value_lines(add_result.stdout).get("status")
    if status != "added":
        print("[vpn-roadwarriors] Router did not confirm peer creation; check logs.")
    else:
        print(f"[vpn-roadwarriors] Router accepted peer {peer_name}.")

    peer_record = {
        "id": peer_name,
        "firstName": first_name,
        "lastName": last_name,
        "comment": comment,
        "publicKey": client_public,
        "privateKey": client_private,
        "allowedAddress": allowed_address,
        "configFile": "",
        "presharedKey": "",
        "allowedIps": allowed_ips,
        "routerAllowed": router_allowed,
        "createdAt": datetime.datetime.utcnow().isoformat() + "Z",
    }

    connection = config["connection"]
    router_endpoint = connection.get("routerPublicIp") or connection.get("routerIp")
    listen_port = server["listenPort"]
    dns = server.get("dns", DEFAULT_DNS)

    client_allowed_ips = [allowed_address]
    for item in allowed_ips:
        if item not in client_allowed_ips:
            client_allowed_ips.append(item)

    config_text = render_client_config(
        client_private=client_private,
        client_address=allowed_address,
        dns=dns,
        peer_name=peer_name,
        server_public=server_public,
    router_ip=router_endpoint,
        listen_port=listen_port,
        preshared_key=peer_record.get("presharedKey", ""),
        allowed_ips=client_allowed_ips,
    )
    file_path = write_client_config_file(peer_name, config_text)
    peer_record["configFile"] = str(file_path)

    config.setdefault("peers", []).append(peer_record)
    save_config(config)

    print("\n[vpn-roadwarriors] New WireGuard peer created successfully:")
    print(f"  Name          : {peer_name}")
    print(f"  Allowed IP    : {allowed_address}")
    print(f"  Private key   : {client_private}")
    print(f"  Public key    : {client_public}")
    print(f"  AllowedIPs    : {', '.join(allowed_ips)}")
    print(f"  Router allow  : {', '.join(router_allowed)}")
    print(f"  Config file   : {file_path}")

    instructions = textwrap.dedent(
        f"""
        Next steps for the user:
          1. Copy the file {file_path} to the user's Windows workstation.
          2. Open the WireGuard desktop app and choose "Import tunnel(s) from file...".
          3. Select the configuration file; the tunnel will be named {peer_name}.
          4. Click "Activate" to establish the VPN connection.
        """
    )
    print(instructions)


def list_peers(config: Dict[str, Any], *, show_indexes: bool = True) -> None:
    peers = config.get("peers", [])
    if not peers:
        print("[vpn-roadwarriors] No WireGuard peers recorded.")
        return
    id_width = max(len("ID"), *(len(str(peer.get("id", ""))) for peer in peers))
    first_width = max(len("First name"), *(len(str(peer.get("firstName", ""))) for peer in peers))
    last_width = max(len("Last name"), *(len(str(peer.get("lastName", ""))) for peer in peers))

    if show_indexes:
        index_width = len(str(len(peers)))
        header = (
            f"{'#':>{index_width}}  {'ID':<{id_width}}  "
            f"{'First name':<{first_width}}  {'Last name':<{last_width}}  Comment"
        )
    else:
        header = f"{'ID':<{id_width}}  {'First name':<{first_width}}  {'Last name':<{last_width}}  Comment"
    print("\nConfigured peers:")
    print(header)
    print("-" * len(header))
    for index, peer in enumerate(peers, start=1):
        comment = peer.get("comment") or ""
        if show_indexes:
            print(
                f"{index:>{index_width}}  {peer.get('id', ''):<{id_width}}  "
                f"{peer.get('firstName', ''):<{first_width}}  {peer.get('lastName', ''):<{last_width}}  {comment}"
            )
        else:
            print(
                f"{peer.get('id', ''):<{id_width}}  {peer.get('firstName', ''):<{first_width}}  {peer.get('lastName', ''):<{last_width}}  {comment}"
            )


def remove_wireguard_peer(config: Dict[str, Any], client: SSHClient) -> None:
    peers = config.get("peers", [])
    if not peers:
        print("[vpn-roadwarriors] No peers to remove.")
        return

    list_peers(config, show_indexes=True)
    while True:
        raw = input("Select peer to remove (number, or press Enter to cancel): ").strip()
        if not raw:
            print("[vpn-roadwarriors] Removal cancelled.")
            return
        if not raw.isdigit():
            print("[vpn-roadwarriors] Please enter a numeric value.")
            continue
        index = int(raw)
        if 1 <= index <= len(peers):
            break
        print("[vpn-roadwarriors] Selection out of range.")

    peer = peers[index - 1]
    public_key = peer.get("publicKey")
    if not public_key:
        print("[vpn-roadwarriors] Selected peer lacks a recorded public key. Nothing to remove.")
        return

    peer_id = peer.get("id") or "(unknown)"
    confirm = input(f"Type 'yes' to confirm removal of peer {peer_id}: ").strip().lower()
    if confirm != "yes":
        print("[vpn-roadwarriors] Removal aborted by user.")
        return

    iface = config["server"]["interfaceName"]
    print(f"[vpn-roadwarriors] Removing peer {peer_id} from router interface {iface}...")
    remove_script = textwrap.dedent(
        f"""
        :local target [/interface/wireguard peers find where interface="{iface}" && public-key="{public_key}"];
        :if ([:len $target] = 0) do={{ :put "status=missing"; }} else={{
          /interface/wireguard peers remove $target;
          :put "status=removed";
        }}
        """
    ).strip()
    result = client.run(remove_script)
    status = parse_key_value_lines(result.stdout).get("status")

    if status != "removed":
        print(f"[vpn-roadwarriors] Router did not remove the peer (status: {status}).")
        return

    print(f"[vpn-roadwarriors] Router removal confirmed for {peer_id}.")
    config["peers"].pop(index - 1)
    save_config(config)
    print(f"[vpn-roadwarriors] Removed peer {peer_id} from local configuration cache.")

    config_path = peer.get("configFile")
    if config_path:
        print(f"[vpn-roadwarriors] Deleting local config file {config_path}...")
        try:
            Path(config_path).unlink(missing_ok=True)  # type: ignore[arg-type]
            print(f"[vpn-roadwarriors] Deleted {config_path}.")
        except OSError:
            print(f"[vpn-roadwarriors] Unable to delete {config_path}; remove it manually if desired.")

    print(f"[vpn-roadwarriors] Peer {peer_id} removed from router and local cache.")


def main() -> None:
    ensure_config_exists()
    config = load_config()
    print_config_summary(config)
    ssh_client: Optional[SSHClient] = None

    while True:
        menu_text, valid_choices = build_menu(config)
        print(menu_text)
        print(TAGLINE)
        print(MODEL_LINE)
        print()
        choice = input("Select an option: ").strip()

        if choice not in valid_choices:
            print(f"[vpn-roadwarriors] Invalid selection. Choose from: {', '.join(sorted(valid_choices))}.")
            continue

        if choice == "6":
            print("[vpn-roadwarriors] Goodbye.")
            break

        if choice == "1":
            ssh_client = ensure_ssh_client(config, ssh_client)
            test_ssh_connection(config, ssh_client)
            continue

        ssh_client = ensure_ssh_client(config, ssh_client)

        if choice == "2":
            ensure_wireguard_server(config, ssh_client, verbose=True)
        elif choice == "3":
            add_wireguard_peer(config, ssh_client)
        elif choice == "4":
            remove_wireguard_peer(config, ssh_client)
        elif choice == "5":
            list_peers(config)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[vpn-roadwarriors] Interrupted by user.")
        sys.exit(1)
