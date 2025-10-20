#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
BASE_RSC_FILE="${SCRIPT_DIR}/02_routeros-7.18-base.rsc"
CONFIG_FILE="${SCRIPT_DIR}/bootstrap_routeros.json"
REMOTE_SCRIPT_NAME="opengwtools-bootstrap.rsc"

GLOBAL_KEYS=(action routerName bridgeIP subnet dhcpStart dhcpEnd dhcpNetAddr dhcpServerDisabled)
declare -Ag GLOBAL_VALUES=()
declare -Ag CONNECTION_VALUES=()
declare -Ag SUGGESTED_VALUES=()

PYTHON_BIN=""

detect_python() {
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN=$(command -v python3)
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN=$(command -v python)
  else
    echo "[bootstrap-routeros] Python is required but not found." >&2
    exit 1
  fi
}

log() {
  printf '[bootstrap-routeros] %s\n' "$*"
}

cleanup_file=""
cleanup() {
  if [[ -n ${cleanup_file} && -f ${cleanup_file} ]]; then
    rm -f "${cleanup_file}" 2>/dev/null || true
  fi
}

trap cleanup EXIT

ensure_config_exists() {
  if [[ -f "${CONFIG_FILE}" ]]; then
    return
  fi

  log "Creating default configuration from base script globals."
  BASE_RSC_FILE="${BASE_RSC_FILE}" CONFIG_FILE="${CONFIG_FILE}" "${PYTHON_BIN}" <<'PY'
import json, os, re
from pathlib import Path

base_path = Path(os.environ["BASE_RSC_FILE"])
config_path = Path(os.environ["CONFIG_FILE"])

globals_map = {}
if base_path.exists():
    pattern = re.compile(r"^\s*:global\s+(\S+)\s+(.+?)\s*$")
    with base_path.open(encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            match = pattern.match(line)
            if not match:
                continue
            name, value = match.groups()
            if name.startswith("#"):
                continue
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            globals_map[name] = value

config = {
    "connection": {
        "sshUser": "admin",
        "sshPort": 22,
        "dhcpIp": "",
        "staticIp": globals_map.get("bridgeIP", "")
    },
    "globals": globals_map
}

config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
PY
}

load_config() {
  ensure_config_exists

  local exports
  exports=$(CONFIG_FILE="${CONFIG_FILE}" "${PYTHON_BIN}" <<'PY'
import json, os, shlex
from pathlib import Path

config_path = Path(os.environ["CONFIG_FILE"])
if not config_path.exists():
    raise SystemExit(f"Configuration file {config_path} is missing.")

with config_path.open(encoding="utf-8") as fh:
    data = json.load(fh)

globals_section = data.get("globals", {})
connection_section = data.get("connection", {})

for key, value in globals_section.items():
    if isinstance(value, bool):
        value = str(value).lower()
    print(f"CFG_GLOBAL_{key}={shlex.quote(str(value))}")

for key, value in connection_section.items():
    if isinstance(value, bool):
        value = str(value).lower()
    print(f"CFG_CONNECTION_{key}={shlex.quote(str(value))}")
PY
)

  if [[ -z ${exports} ]]; then
    log "Failed to parse configuration file." >&2
    exit 1
  fi

  eval "${exports}"

  for key in "${GLOBAL_KEYS[@]}"; do
    local var="CFG_GLOBAL_${key}"
    GLOBAL_VALUES["${key}"]=${!var-}
  done

  CONNECTION_VALUES[sshUser]=${CFG_CONNECTION_sshUser-admin}
  CONNECTION_VALUES[sshPort]=${CFG_CONNECTION_sshPort-22}
  CONNECTION_VALUES[dhcpIp]=${CFG_CONNECTION_dhcpIp-}
  CONNECTION_VALUES[staticIp]=${CFG_CONNECTION_staticIp-${GLOBAL_VALUES[bridgeIP]-}}
}

save_config() {
  export CFG_GLOBAL_KEYS="$(IFS=,; echo "${GLOBAL_KEYS[*]}")"
  for key in "${GLOBAL_KEYS[@]}"; do
    export "CFG_GLOBAL_${key}"="${GLOBAL_VALUES[$key]}"
  done
  export CFG_CONNECTION_sshUser="${CONNECTION_VALUES[sshUser]}"
  export CFG_CONNECTION_sshPort="${CONNECTION_VALUES[sshPort]}"
  export CFG_CONNECTION_dhcpIp="${CONNECTION_VALUES[dhcpIp]}"
  export CFG_CONNECTION_staticIp="${CONNECTION_VALUES[staticIp]}"

  CONFIG_FILE="${CONFIG_FILE}" "${PYTHON_BIN}" <<'PY'
import json, os
from pathlib import Path

config_path = Path(os.environ["CONFIG_FILE"])
keys = os.environ["CFG_GLOBAL_KEYS"].split(",")

globals_section = {}
for key in keys:
    env_key = f"CFG_GLOBAL_{key}"
    value = os.environ.get(env_key, "")
    if key == "subnet":
        try:
            globals_section[key] = int(value)
            continue
        except ValueError:
            pass
    globals_section[key] = value

connection_section = {
    "sshUser": os.environ.get("CFG_CONNECTION_sshUser", "admin"),
    "sshPort": int(os.environ.get("CFG_CONNECTION_sshPort", "22")),
    "dhcpIp": os.environ.get("CFG_CONNECTION_dhcpIp", ""),
    "staticIp": os.environ.get("CFG_CONNECTION_staticIp", "")
}

data = {
    "connection": connection_section,
    "globals": globals_section
}

config_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
PY
}

validate_ipv4() {
  local value="$1"
  if [[ ! ${value} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    return 1
  fi
  IFS='.' read -r o1 o2 o3 o4 <<< "${value}"
  for octet in "$o1" "$o2" "$o3" "$o4"; do
    if (( octet < 0 || octet > 255 )); then
      return 1
    fi
  done
  return 0
}

validate_prefix() {
  local value="$1"
  if [[ ! ${value} =~ ^[0-9]{1,2}$ ]]; then
    return 1
  fi
  if (( value < 1 || value > 32 )); then
    return 1
  fi
  return 0
}

validate_port() {
  local value="$1"
  if [[ ! ${value} =~ ^[0-9]{1,5}$ ]]; then
    return 1
  fi
  if (( value < 1 || value > 65535 )); then
    return 1
  fi
  return 0
}

validate_cidr() {
  local value="$1"
  if [[ ${value} != */* ]]; then
    return 1
  fi
  local ip="${value%%/*}"
  local prefix="${value##*/}"
  validate_ipv4 "${ip}" && validate_prefix "${prefix}"
}

prompt_for_value() {
  local label="$1"
  local default_value="$2"
  local validator="${3:-}"
  local input

  while true; do
    read -r -p "${label} [${default_value}]: " input || exit 1
    if [[ -z ${input} ]]; then
      input="${default_value}"
    fi
    if [[ -z ${validator} ]]; then
      printf '%s' "${input}"
      return
    fi
    if "${validator}" "${input}"; then
      printf '%s' "${input}"
      return
    fi
    log "Invalid value '${input}' for ${label}."
  done
}

calculate_suggestions() {
  local dhcp_ip="$1"
  local prefix="$2"
  local previous_router="${GLOBAL_VALUES[routerName]-}"

  local raw
  raw=$(PY_DHCP_IP="${dhcp_ip}" PY_PREFIX="${prefix}" PY_PREV_ROUTER="${previous_router}" "${PYTHON_BIN}" <<'PY'
import ipaddress, os

dhcp_ip = os.environ["PY_DHCP_IP"]
prefix = int(os.environ["PY_PREFIX"])
prev_router = os.environ.get("PY_PREV_ROUTER", "").strip()

network = ipaddress.ip_network(f"{dhcp_ip}/{prefix}", strict=False)
bridge_ip = network[-2]

hosts = list(network.hosts())
if not hosts:
    raise SystemExit("No usable hosts in calculated network.")

pool_start = hosts[0]
pool_end = hosts[-1]
if len(hosts) >= 8:
    pool_start = hosts[-min(31, len(hosts))]
    pool_end = hosts[-5]

if pool_end == bridge_ip:
    idx = hosts.index(bridge_ip)
    pool_end = hosts[idx - 1] if idx > 0 else hosts[0]

if pool_start >= pool_end:
    pool_start = hosts[0]
    pool_end = hosts[-1]
    if pool_end == bridge_ip:
        pool_end = hosts[-2]

if prev_router and prev_router.lower() != "opengwtools":
    router_name = prev_router
else:
    last_octet = dhcp_ip.split('.')[-1]
    router_name = f"opengwtools-{last_octet}"

suggestions = {
    "routerName": router_name,
    "bridgeIP": str(bridge_ip),
    "dhcpStart": str(pool_start),
    "dhcpEnd": str(pool_end),
    "dhcpNetAddr": f"{network.network_address}/{network.prefixlen}"
}

for key, value in suggestions.items():
    print(f"{key}\t{value}")
PY
  )

  for key in "${!SUGGESTED_VALUES[@]}"; do
    unset "SUGGESTED_VALUES[$key]"
  done
  while IFS=$'\t' read -r key value; do
    [[ -z ${key} ]] && continue
    SUGGESTED_VALUES["${key}"]="${value}"
  done <<< "${raw}"
}

validate_dhcp_range() {
  local start_ip="$1"
  local end_ip="$2"
  local cidr="$3"
  local gateway="$4"

  local result
  result=$(PY_START="${start_ip}" PY_END="${end_ip}" PY_CIDR="${cidr}" PY_GATEWAY="${gateway}" "${PYTHON_BIN}" <<'PY'
import ipaddress, os

start = ipaddress.ip_address(os.environ["PY_START"])
end = ipaddress.ip_address(os.environ["PY_END"])
network = ipaddress.ip_network(os.environ["PY_CIDR"], strict=False)
gateway = ipaddress.ip_address(os.environ["PY_GATEWAY"])

if start not in network or end not in network:
    raise SystemExit("out-of-network")
if start > end:
    raise SystemExit("start-after-end")
if gateway in (start, end):
    raise SystemExit("conflict-gateway")
print("ok")
PY
  ) || return 1
  [[ ${result} == "ok" ]]
}

generate_routeros_script() {
  local output_path="$1"
  BASE_RSC_FILE="${BASE_RSC_FILE}" CONFIG_FILE="${CONFIG_FILE}" OUTPUT_PATH="${output_path}" "${PYTHON_BIN}" <<'PY'
import json, os, re
from pathlib import Path

base_path = Path(os.environ["BASE_RSC_FILE"])
config_path = Path(os.environ["CONFIG_FILE"])
output_path = Path(os.environ["OUTPUT_PATH"])

with config_path.open(encoding="utf-8") as fh:
    data = json.load(fh)

globals_section = data.get("globals", {})

pattern = re.compile(r"^(\s*):global\s+(\S+)\s+(.+?)(\s*)$")

def format_value(value):
    if isinstance(value, (int, float)):
        return str(value)
    value_str = str(value)
    simple_token = re.compile(r"^[A-Za-z0-9._:-]+$")
    ip_pattern = re.compile(r"^[0-9]{1,3}(\.[0-9]{1,3}){3}(/\d{1,2})?$")
    if simple_token.match(value_str) or ip_pattern.match(value_str):
        return value_str
    escaped = value_str.replace('"', '\\"')
    return f'"{escaped}"'

lines = []
with base_path.open(encoding="utf-8") as fh:
    for raw_line in fh:
        match = pattern.match(raw_line.rstrip('\n'))
        if match:
            prefix, name, _, suffix = match.groups()
            if name in globals_section:
                formatted_value = format_value(globals_section[name])
                new_line = f"{prefix}:global {name} {formatted_value}{suffix}\n"
                lines.append(new_line)
                continue
        lines.append(raw_line)

output_path.write_text(''.join(lines), encoding="utf-8")
PY
}

upload_and_apply() {
  local local_script="$1"
  local user="$2"
  local port="$3"
  local target_ip="$4"

  log "Uploading updated configuration script to ${target_ip}."
  scp -q -P "${port}" -o StrictHostKeyChecking=accept-new "${local_script}" "${user}@${target_ip}:${REMOTE_SCRIPT_NAME}"

  log "Registering and executing script on MikroTik (session may disconnect)."
  set +e
  ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p "${port}" "${user}@${target_ip}" \
    ':local scriptName "opengwtools-bootstrap"; :local scriptFile "opengwtools-bootstrap.rsc"; :local existing [/system script find name=$scriptName]; if ([:len $existing] > 0) do={ /system script set $existing source=[/file get $scriptFile contents]; } else={ /system script add name=$scriptName source=[/file get $scriptFile contents]; /system script set [/system script find name=$scriptName] comment="Managed by opengwtools bootstrap"; }; /system script run $scriptName;'
  local exit_code=$?
  set -e
  if (( exit_code != 0 )); then
    log "SSH command exited with status ${exit_code}. This can happen when the router applies new network settings."
  fi
}

verify_new_connection() {
  local user="$1"
  local port="$2"
  local target_ip="$3"

  log "Waiting for router to come back on ${target_ip}..."
  for attempt in {1..8}; do
    if ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 -p "${port}" "${user}@${target_ip}" '/system identity print' >/dev/null 2>&1; then
      log "SSH connectivity verified on ${target_ip}."
      return 0
    fi
    sleep 5
  done
  log "Unable to verify SSH connectivity on ${target_ip}. Please check the router manually."
  return 1
}

ensure_remote_script_registered() {
  local user="$1"
  local port="$2"
  local target_ip="$3"

  log "Ensuring bootstrap script is stored on ${target_ip}."
  set +e
  ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p "${port}" "${user}@${target_ip}" \
    ':local scriptName "opengwtools-bootstrap"; :local scriptFile "opengwtools-bootstrap.rsc"; :local existing [/system script find name=$scriptName]; if ([:len $existing] > 0) do={ /system script set $existing source=[/file get $scriptFile contents]; } else={ /system script add name=$scriptName source=[/file get $scriptFile contents]; /system script set [/system script find name=$scriptName] comment="Managed by opengwtools bootstrap"; };'
  local exit_code=$?
  set -e
  if (( exit_code != 0 )); then
    log "Failed to confirm script storage (exit ${exit_code}). You can re-run the helper after connectivity is restored."
  else
    log "Bootstrap script is present on the router."
  fi
}

display_router_identity() {
  local user="$1"
  local port="$2"
  local target_ip="$3"

  log "Checking current router identity on ${target_ip} (enter password if prompted)."
  set +e
  local output
  output=$(ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p "${port}" "${user}@${target_ip}" '/system identity print' 2>/dev/null)
  local exit_code=$?
  set -e
  if (( exit_code != 0 )); then
    log "Unable to read router identity (exit ${exit_code})."
    return ${exit_code}
  fi

  local identity
  identity=$(printf '%s\n' "${output}" | grep -i '^ *name:' | head -n1 | sed -E 's/^ *[Nn][Aa][Mm][Ee]: *//')
  if [[ -n ${identity} ]]; then
    log "Router identity: ${identity}"
  else
    log "Router identity output:\n${output}"
  fi
  return 0
}

reset_known_host_entry() {
  local host="$1"
  local port="$2"
  if ! command -v ssh-keygen >/dev/null 2>&1; then
    return
  fi

  local cleaned=0
  if [[ ${port} = "22" || ${port} = 22 ]]; then
    if ssh-keygen -R "${host}" >/dev/null 2>&1; then
      cleaned=1
    fi
  fi
  if ssh-keygen -R "[${host}]:${port}" >/dev/null 2>&1; then
    cleaned=1
  fi

  if (( cleaned )); then
    log "Reset local SSH host key entry for ${host}:${port}."
  fi
}

print_bootstrap_summary() {
  local _user="$1"
  local _port="$2"
  local target_ip="$3"

  local bridge_ip="${GLOBAL_VALUES[bridgeIP]:-${target_ip}}"
  local subnet="${GLOBAL_VALUES[subnet]:-24}"
  local dhcp_start="${GLOBAL_VALUES[dhcpStart]:-}"
  local dhcp_end="${GLOBAL_VALUES[dhcpEnd]:-}"
  local dhcp_net="${GLOBAL_VALUES[dhcpNetAddr]:-}"
  local router_name="${GLOBAL_VALUES[routerName]:-opengwtools}"
  local dhcp_disabled="${GLOBAL_VALUES[dhcpServerDisabled]:-no}"

  printf '\n  Post-bootstrap verification (Winbox recommended):\n\n'
  printf '    - Reconnect with Winbox to %s (or the IP you assigned).\n' "${bridge_ip}"
  printf '    - System → Identity should show: %s\n' "${router_name}"
  printf '    - Interfaces renamed: ether1 → ether1-wan1; additional ports tagged as ether*-lan#.\n'
  printf '    - Bridge interface "bridge" present with static address %s/%s (comment defconf).\n' "${bridge_ip}" "${subnet}"
  printf '    - IP → DNS allows remote requests and contains static entry router.lan → %s.\n' "${bridge_ip}"
  printf '    - IP → Pool lists "default-dhcp" covering %s-%s.\n' "${dhcp_start}" "${dhcp_end}"
  printf '    - IP → DHCP Server has "defconf" on bridge with network %s (disabled=%s).\n' "${dhcp_net}" "${dhcp_disabled}"
  printf '    - IP → DHCP Client enabled on ether1-wan1 when a dedicated WAN port exists.\n'
  printf '    - IP → Firewall → NAT includes defconf masquerade for out-interface-list=WAN.\n'
  printf '    - IP → Firewall → Filter retains defconf accept/drop baseline plus fasttrack rule.\n'
  printf '    - IP → Neighbor Discovery and MAC server lists restricted to LAN.\n'
  printf '\n  No SSH summary is collected automatically; confirm the above items through the Winbox UI.\n\n'
}

print_configuration_summary() {
  printf '  Connection:\n'
  for key in sshUser sshPort dhcpIp staticIp; do
    local value=${CONNECTION_VALUES[$key]:-}
    [[ -z ${value} ]] && value="(not set)"
    printf '    %-10s : %s\n' "${key}" "${value}"
  done

  printf '\n  Globals:\n'
  for key in "${GLOBAL_KEYS[@]}"; do
    local value=${GLOBAL_VALUES[$key]:-}
    [[ -z ${value} ]] && value="(not set)"
    printf '    %-10s : %s\n' "${key}" "${value}"
  done
}

pause_for_user() {
  read -r -p $'\nPress Enter to return to the menu... ' _ || true
}

ensure_connection_detail() {
  local name="$1"
  local label="$2"
  local validator="${3:-}"
  local current=${CONNECTION_VALUES[$name]:-}
  local new_value

  if [[ -n ${current} ]]; then
    return 0
  fi

  new_value=$(prompt_for_value "${label}" "${current}" "${validator}")
  CONNECTION_VALUES[$name]="${new_value}"
  save_config
}

test_ssh_connection() {
  load_config

  local ssh_user=${CONNECTION_VALUES[sshUser]:-admin}
  local ssh_port=${CONNECTION_VALUES[sshPort]:-22}
  local default_target=${CONNECTION_VALUES[dhcpIp]:-}
  if [[ -z ${default_target} ]]; then
    default_target=${CONNECTION_VALUES[staticIp]:-}
  fi

  local target
  target=$(prompt_for_value "Router IP to test" "${default_target}" validate_ipv4)
  if [[ -z ${CONNECTION_VALUES[dhcpIp]:-} ]]; then
    CONNECTION_VALUES[dhcpIp]="${target}"
  fi
  save_config

  display_router_identity "${ssh_user}" "${ssh_port}" "${target}"
}

interactive_edit_configuration() {
  load_config

  log "Collecting connection details."
  local dhcp_ip
  dhcp_ip=$(prompt_for_value "Current DHCP IP of MikroTik" "${CONNECTION_VALUES[dhcpIp]:-}" validate_ipv4)
  CONNECTION_VALUES[dhcpIp]="${dhcp_ip}"

  local ssh_user
  ssh_user=$(prompt_for_value "SSH username" "${CONNECTION_VALUES[sshUser]:-admin}" )
  CONNECTION_VALUES[sshUser]="${ssh_user}"

  local ssh_port
  ssh_port=$(prompt_for_value "SSH port" "${CONNECTION_VALUES[sshPort]:-22}" validate_port)
  CONNECTION_VALUES[sshPort]="${ssh_port}"

  display_router_identity "${ssh_user}" "${ssh_port}" "${dhcp_ip}" || true

  local subnet
  subnet=$(prompt_for_value "LAN subnet prefix length" "${GLOBAL_VALUES[subnet]:-24}" validate_prefix)
  GLOBAL_VALUES[subnet]="${subnet}"

  calculate_suggestions "${dhcp_ip}" "${subnet}"

  log "Configure RouterOS globals (press Enter to accept defaults)."
  local router_name_default
  router_name_default=${SUGGESTED_VALUES[routerName]:-${GLOBAL_VALUES[routerName]:-opengwtools}}
  GLOBAL_VALUES[routerName]="$(prompt_for_value "Router identity" "${router_name_default}" )"

  local bridge_default
  bridge_default=${SUGGESTED_VALUES[bridgeIP]:-${GLOBAL_VALUES[bridgeIP]:-}}
  GLOBAL_VALUES[bridgeIP]="$(prompt_for_value "Bridge static IP" "${bridge_default}" validate_ipv4)"

  local cidr_default
  cidr_default=${SUGGESTED_VALUES[dhcpNetAddr]:-${GLOBAL_VALUES[dhcpNetAddr]:-${bridge_default}/${subnet}}}
  GLOBAL_VALUES[dhcpNetAddr]="$(prompt_for_value "LAN network (CIDR)" "${cidr_default}" validate_cidr)"

  local dhcp_start
  local dhcp_end
  while true; do
    local start_default=${SUGGESTED_VALUES[dhcpStart]:-${GLOBAL_VALUES[dhcpStart]:-}}
  local ssh_command=':local identity [/system identity get name];
:local bridgeAddr "";
:local dhcpNetwork "";
:local dhcpGateway "";
:local dhcpPool "";
:local dhcpDisabled "";

/ip address {
  :local addrId [find where interface="bridge" && comment="defconf"];
  :if ([:len $addrId] = 0) do={ :set addrId [find where interface="bridge"]; }
  :if ([:len $addrId] > 0) do={ :set bridgeAddr [/ip address get $addrId address]; }
}

/ip dhcp-server {
  :local srvId [find where name="defconf"];
  :if ([:len $srvId] > 0) do={ :set dhcpDisabled [/ip dhcp-server get $srvId disabled]; }
}

/ip dhcp-server network {
  :local netId [find where comment="defconf"];
  :if ([:len $netId] = 0) do={ :set netId [find]; }
  :if ([:len $netId] > 0) do={
    :set dhcpNetwork [/ip dhcp-server network get $netId address];
    :set dhcpGateway [/ip dhcp-server network get $netId gateway];
  }
}

/ip pool {
  :local poolId [find where name="default-dhcp"];
  :if ([:len $poolId] > 0) do={ :set dhcpPool [/ip pool get $poolId ranges]; }
}

:put ("identity=" . $identity);
:put ("bridgeAddress=" . $bridgeAddr);
:put ("dhcpNetwork=" . $dhcpNetwork);
:put ("dhcpGateway=" . $dhcpGateway);
:put ("dhcpPool=" . $dhcpPool);
:put ("dhcpServerDisabled=" . $dhcpDisabled);
'

  local raw
  local exit_code

  set +e
  raw=$(ssh -T -o BatchMode=yes -o PreferredAuthentications=publickey,password -o PubkeyAuthentication=no -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p "${port}" "${user}@${target_ip}" "${ssh_command}")
  exit_code=$?
  set -e

  if (( exit_code != 0 && exit_code == 255 )); then
    if command -v sshpass >/dev/null 2>&1; then
      local summary_pass
      read -rs -p "[bootstrap-routeros] Router password (for summary): " summary_pass || summary_pass=""
      printf '\n'
      if [[ -n ${summary_pass} ]]; then
        set +e
        SSHPASS="${summary_pass}" raw=$(sshpass -e ssh -T -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p "${port}" "${user}@${target_ip}" "${ssh_command}")
        exit_code=$?
        set -e
      fi
      unset summary_pass SSHPASS
    fi
  fi

    dhcp_start=$(prompt_for_value "DHCP pool start" "${start_default}" validate_ipv4)
    dhcp_end=$(prompt_for_value "DHCP pool end" "${end_default}" validate_ipv4)
    if validate_dhcp_range "${dhcp_start}" "${dhcp_end}" "${GLOBAL_VALUES[dhcpNetAddr]}" "${GLOBAL_VALUES[bridgeIP]}"; then
      break
    fi
    log "DHCP range is invalid for the selected network. Please try again."
  done
  GLOBAL_VALUES[dhcpStart]="${dhcp_start}"
  GLOBAL_VALUES[dhcpEnd]="${dhcp_end}"

  local disable_default=${GLOBAL_VALUES[dhcpServerDisabled]:-no}
  local prompt_suffix="[y/N]"
  if [[ ${disable_default} == "yes" ]]; then
    prompt_suffix="[Y/n]"
  fi
  local disable_dhcp_answer
  read -r -p "Disable MikroTik DHCP server to avoid conflicts? ${prompt_suffix}: " disable_dhcp_answer || exit 1
  if [[ -z ${disable_dhcp_answer} ]]; then
    disable_dhcp_answer="${disable_default}"
  fi
  local disable_clean
  disable_clean=$(printf '%s' "${disable_dhcp_answer}" | tr '[:upper:]' '[:lower:]')
  case "${disable_clean}" in
    y|yes) GLOBAL_VALUES[dhcpServerDisabled]="yes" ;;
    n|no) GLOBAL_VALUES[dhcpServerDisabled]="no" ;;
    *) GLOBAL_VALUES[dhcpServerDisabled]="no" ;;
  esac

  GLOBAL_VALUES[action]="apply"
  CONNECTION_VALUES[staticIp]="${GLOBAL_VALUES[bridgeIP]}"

  save_config
  log "Configuration saved to ${CONFIG_FILE}."
}

deploy_bootstrap_configuration() {
  load_config

  ensure_connection_detail sshUser "SSH username" 
  ensure_connection_detail sshPort "SSH port" validate_port
  ensure_connection_detail dhcpIp "Current DHCP IP of MikroTik" validate_ipv4

  local ssh_user=${CONNECTION_VALUES[sshUser]}
  local ssh_port=${CONNECTION_VALUES[sshPort]}
  local dhcp_ip=${CONNECTION_VALUES[dhcpIp]}

  if [[ -z ${GLOBAL_VALUES[bridgeIP]:-} || -z ${GLOBAL_VALUES[subnet]:-} ]]; then
    log "Bridge IP or subnet is not set. Use option 3) Edit configuration first."
    return 1
  fi

  display_router_identity "${ssh_user}" "${ssh_port}" "${dhcp_ip}" || true

  GLOBAL_VALUES[action]="apply"
  CONNECTION_VALUES[staticIp]="${GLOBAL_VALUES[bridgeIP]}"
  save_config

  local temp_script
  temp_script=$(mktemp)
  cleanup_file="${temp_script}"
  generate_routeros_script "${temp_script}"

  upload_and_apply "${temp_script}" "${ssh_user}" "${ssh_port}" "${dhcp_ip}"

  log "Allowing the router to apply configuration..."
  sleep 10

  reset_known_host_entry "${GLOBAL_VALUES[bridgeIP]}" "${ssh_port}"

  if verify_new_connection "${ssh_user}" "${ssh_port}" "${GLOBAL_VALUES[bridgeIP]}"; then
    ensure_remote_script_registered "${ssh_user}" "${ssh_port}" "${GLOBAL_VALUES[bridgeIP]}"
    print_bootstrap_summary "${ssh_user}" "${ssh_port}" "${GLOBAL_VALUES[bridgeIP]}"
    log "Tip: run '/log print follow' on the router to review bootstrap events."
  fi
}

main_menu() {
  detect_python
  ensure_config_exists

  while true; do
    load_config
    printf '\n === MikroTik CHR Bootstrap Utility ===\n\n'
    printf '  Current configuration:\n\n'
    print_configuration_summary
    printf '\n  Menu:\n\n'
    printf '  1) Test SSH connection to MikroTik\n'
    printf '  2) Deploy (upload and run) Bootstrap config\n'
    printf '  3) Edit configuration\n'
    printf '  4) Exit\n\n'
    printf 'Creative spark, AI prompting, and continuous debugging by: Attila Macskasy\n'
    printf 'Code generated using: GPT-5 Codex (Preview) — Premium Model x1\n'
    printf '(c) 2025 OpenLandingZone \\ OpenGWTools \\ Bootstrap Utility 1.1\n\n'

    read -r -p 'Select an option [1-4]: ' choice || exit 0
    case ${choice} in
      1)
        test_ssh_connection
        pause_for_user
        ;;
      2)
        deploy_bootstrap_configuration || true
        pause_for_user
        ;;
      3)
        interactive_edit_configuration
        pause_for_user
        ;;
      4)
        log "Goodbye."
        exit 0
        ;;
      *)
        log "Invalid selection '${choice}'. Please choose 1-4."
        pause_for_user
        ;;
    esac
  done
}

main_menu "$@"
