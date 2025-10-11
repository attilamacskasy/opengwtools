#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
CONFIG_FILE="${SCRIPT_DIR}/deploy_chr.json"
SSH_CONTROL_SOCKET=$(mktemp -u "/tmp/deploy_chr_ssh_mux_XXXXXX")
declare -a SSH_COMMON_OPTS=(-o StrictHostKeyChecking=accept-new -o ControlPath="${SSH_CONTROL_SOCKET}")
declare -a SCP_COMMON_OPTS=(-o StrictHostKeyChecking=accept-new -o ControlPath="${SSH_CONTROL_SOCKET}")
SSH_CONNECTED=0

log() {
  printf '[deploy-chr] %s\n' "$*"
}

reset_ssh_options() {
  SSH_CONTROL_SOCKET=$(mktemp -u "/tmp/deploy_chr_ssh_mux_XXXXXX")
  SSH_COMMON_OPTS=(-o StrictHostKeyChecking=accept-new -o ControlPath="${SSH_CONTROL_SOCKET}")
  SCP_COMMON_OPTS=(-o StrictHostKeyChecking=accept-new -o ControlPath="${SSH_CONTROL_SOCKET}")
}

ensure_config_exists() {
  if [[ -f "${CONFIG_FILE}" ]]; then
    return
  fi

  cat >"${CONFIG_FILE}" <<'EOF'
{
  "proxmox": {
    "host": "172.22.22.252",
    "user": "root",
    "node": "pve-01",
    "bridge": "vmbr0",
    "storage": "local-lvm"
  },
  "vm": {
    "id": "auto",
    "name": "chr-terraform-lab",
    "memory": 512,
    "cores": 1
  },
  "image": {
    "version": "7.20.1",
    "remoteDir": "/var/lib/vz/template/iso"
  }
}
EOF

  log "Created default configuration at ${CONFIG_FILE}."
}

close_ssh_master() {
  local socket="${SSH_CONTROL_SOCKET:-}"

  if [[ -z ${socket} ]]; then
    reset_ssh_options
    return
  fi

  if [[ ${SSH_CONNECTED:-0} -eq 1 && -n ${SSH_TARGET:-} ]]; then
    ssh -S "${socket}" "${SSH_TARGET}" -O exit >/dev/null 2>&1 || true
  fi

  rm -f "${socket}" 2>/dev/null || true
  SSH_CONNECTED=0
  reset_ssh_options
}

cleanup() {
  close_ssh_master
}

trap cleanup EXIT

load_config() {
  ensure_config_exists

  local python_bin
  if command -v python3 >/dev/null 2>&1; then
    python_bin=python3
  else
    python_bin=python
  fi

  local exports
  exports=$(CONFIG_FILE_PATH="${CONFIG_FILE}" "${python_bin}" <<'PY'
import json, os, shlex
from pathlib import Path

path = Path(os.environ["CONFIG_FILE_PATH"])
if not path.exists():
    raise SystemExit(f"Configuration file '{path}' not found.")

with path.open(encoding="utf-8") as fh:
    data = json.load(fh)

proxmox = data.get("proxmox", {})
vm = data.get("vm", {})
image = data.get("image", {})

flat = {
    "CONFIG_PROXMOX_HOST": proxmox.get("host", ""),
    "CONFIG_PROXMOX_USER": proxmox.get("user", ""),
    "CONFIG_PROXMOX_NODE": proxmox.get("node", ""),
    "CONFIG_PROXMOX_BRIDGE": proxmox.get("bridge", ""),
    "CONFIG_PROXMOX_STORAGE": proxmox.get("storage", ""),
    "CONFIG_VM_ID": vm.get("id", "auto"),
    "CONFIG_VM_NAME": vm.get("name", "chr-terraform-lab"),
    "CONFIG_VM_MEMORY": vm.get("memory", 512),
    "CONFIG_VM_CORES": vm.get("cores", 1),
    "CONFIG_IMAGE_VERSION": image.get("version", "7.20.1"),
    "CONFIG_IMAGE_REMOTEDIR": image.get("remoteDir", "/var/lib/vz/template/iso")
}

for key, value in flat.items():
    if isinstance(value, bool):
        value = str(value).lower()
    print(f"{key}={shlex.quote(str(value))}")
PY
)

  if [[ -z ${exports} ]]; then
    log "Failed to parse configuration."
    exit 1
  fi

  eval "${exports}"

  CONFIG_PROXMOX_NODE=${CONFIG_PROXMOX_NODE:-${CONFIG_PROXMOX_HOST}}
  update_runtime_variables
}

save_config() {
  local python_bin
  if command -v python3 >/dev/null 2>&1; then
    python_bin=python3
  else
    python_bin=python
  fi

  CONFIG_PROXMOX_NODE=${CONFIG_PROXMOX_NODE:-${CONFIG_PROXMOX_HOST}}

  "${python_bin}" - <<'PY' "${CONFIG_FILE}"
import json, os, sys
path = sys.argv[1]

host = os.environ["CONFIG_PROXMOX_HOST"]
user = os.environ["CONFIG_PROXMOX_USER"]
node = os.environ.get("CONFIG_PROXMOX_NODE", host)
bridge = os.environ["CONFIG_PROXMOX_BRIDGE"]
storage = os.environ["CONFIG_PROXMOX_STORAGE"]
vm_id = os.environ["CONFIG_VM_ID"]
vm_name = os.environ["CONFIG_VM_NAME"]
vm_memory = int(os.environ["CONFIG_VM_MEMORY"])
vm_cores = int(os.environ["CONFIG_VM_CORES"])
version = os.environ["CONFIG_IMAGE_VERSION"]
remote_dir = os.environ["CONFIG_IMAGE_REMOTEDIR"]

try:
    vm_id_val = int(vm_id)
except ValueError:
    vm_id_val = vm_id

config = {
    "proxmox": {
        "host": host,
        "user": user,
        "node": node,
        "bridge": bridge,
        "storage": storage
    },
    "vm": {
        "id": vm_id_val,
        "name": vm_name,
        "memory": vm_memory,
        "cores": vm_cores
    },
    "image": {
        "version": version,
        "remoteDir": remote_dir
    }
}

with open(path, "w", encoding="utf-8") as fh:
    json.dump(config, fh, indent=2)
    fh.write("\n")
PY
}

update_runtime_variables() {
  SSH_TARGET="${CONFIG_PROXMOX_USER}@${CONFIG_PROXMOX_HOST}"
  CHR_ARCHIVE="chr-${CONFIG_IMAGE_VERSION}.img.zip"
  CHR_IMAGE="chr-${CONFIG_IMAGE_VERSION}.img"
  CHR_QCOW2="chr-${CONFIG_IMAGE_VERSION}.qcow2"
  REMOTE_RAW_PATH="${CONFIG_IMAGE_REMOTEDIR}/${CHR_IMAGE}"
  REMOTE_IMAGE_PATH="${CONFIG_IMAGE_REMOTEDIR}/${CHR_QCOW2}"
}

ensure_ssh_connection() {
  if [[ ${SSH_CONNECTED:-0} -eq 1 ]]; then
    return
  fi

  log "Connecting to ${SSH_TARGET} (password prompt may appear)..."
  ssh \
    -o StrictHostKeyChecking=accept-new \
    -o ControlMaster=auto \
    -o ControlPersist=600 \
    -o ControlPath="${SSH_CONTROL_SOCKET}" \
    "${SSH_TARGET}" "true"

  SSH_CONNECTED=1
}

run_remote() {
  local log_command=1
  if [[ ${1:-} == "--silent" ]]; then
    log_command=0
    shift
  fi

  local cmd="$*"

  ensure_ssh_connection

  (( log_command )) && log "remote: ${cmd}"

  local cmd_escaped
  printf -v cmd_escaped '%q' "${cmd}"

  ssh "${SSH_COMMON_OPTS[@]}" "${SSH_TARGET}" bash -lc "${cmd_escaped}"
}

copy_to_remote() {
  ensure_ssh_connection
  scp "${SCP_COMMON_OPTS[@]}" "$1" "${SSH_TARGET}:$2"
}

resolve_new_vmid() {
  run_remote --silent "bash -lc 'shopt -s nullglob; last=99; for f in /etc/pve/qemu-server/*.conf; do id=\${f##*/}; id=\${id%.conf}; [[ \$id =~ ^[0-9]+$ ]] || continue; (( id > last )) && last=\$id; done; echo \$((last + 1))'" | tr -d '\r\n'
}

lookup_existing_vmid() {
  local configured_id="${CONFIG_VM_ID}"

  if [[ ${configured_id} =~ ^[0-9]+$ ]]; then
    if run_remote --silent "qm status ${configured_id}" >/dev/null 2>&1; then
      printf '%s' "${configured_id}"
      return
    fi
  fi

  local listing
  listing=$(run_remote --silent "qm list | awk 'NR>1 {print \$1\":\"\$2}'") || return

  while IFS=":" read -r id name; do
    [[ -z ${id} ]] && continue
    if [[ ${name} == "${CONFIG_VM_NAME}" ]]; then
      printf '%s' "${id}"
      return
    fi
  done <<< "${listing}"
}

determine_target_vmid() {
  local configured_id="${CONFIG_VM_ID}"

  if [[ ${configured_id} =~ ^[0-9]+$ ]]; then
    printf '%s' "${configured_id}"
    return
  fi

  local new_id
  new_id=$(resolve_new_vmid)
  printf '%s' "${new_id}"
}

ensure_vm_stopped() {
  local vmid="$1"
  local status

  status=$(run_remote --silent "qm status ${vmid}" 2>/dev/null | awk '{print $2}') || status="unknown"

  if [[ ${status} == "running" ]]; then
    log "VM ${vmid} is running; requesting shutdown..."
    run_remote "qm shutdown ${vmid}" || true

    for _ in {1..30}; do
      sleep 2
      status=$(run_remote --silent "qm status ${vmid}" 2>/dev/null | awk '{print $2}') || status="unknown"
      if [[ ${status} == "stopped" || ${status} == "down" ]]; then
        log "VM ${vmid} is now stopped."
        return
      fi
    done

    log "Graceful shutdown timed out; forcing stop."
    run_remote "qm stop ${vmid}" || true
  fi
}

prepare_image() {
  local work_dir="$1"

  log "Downloading MikroTik CHR ${CONFIG_IMAGE_VERSION} raw image archive..."
  curl -fsSL "https://download.mikrotik.com/routeros/${CONFIG_IMAGE_VERSION}/${CHR_ARCHIVE}" -o "${work_dir}/${CHR_ARCHIVE}"

  log "Extracting raw disk image..."
  unzip -p "${work_dir}/${CHR_ARCHIVE}" > "${work_dir}/${CHR_IMAGE}"
  chmod 644 "${work_dir}/${CHR_IMAGE}"
  LOCAL_RAW_IMAGE="${work_dir}/${CHR_IMAGE}"
}

deploy_vm() {
  load_config
  ensure_ssh_connection

  local existing_vmid
  existing_vmid=$(lookup_existing_vmid || true)

  local vmid
  if [[ -n ${existing_vmid} ]]; then
    vmid=${existing_vmid}
  else
    vmid=$(determine_target_vmid)
  fi

  log "Preparing deployment for VM ${vmid} (${CONFIG_VM_NAME})"

  local work_dir
  work_dir=$(mktemp -d)
  trap 'rm -rf "${work_dir}"' RETURN

  prepare_image "${work_dir}"

  log "Ensuring remote image directory ${CONFIG_IMAGE_REMOTEDIR} exists..."
  run_remote "mkdir -p '${CONFIG_IMAGE_REMOTEDIR}'"

  log "Uploading image to Proxmox host..."
  copy_to_remote "${LOCAL_RAW_IMAGE}" "${REMOTE_RAW_PATH}"

  log "Converting raw image to qcow2 on Proxmox host..."
  run_remote "rm -f '${REMOTE_IMAGE_PATH}'"
  run_remote "qemu-img convert -f raw -O qcow2 '${REMOTE_RAW_PATH}' '${REMOTE_IMAGE_PATH}'"
  run_remote "chmod 644 '${REMOTE_IMAGE_PATH}'"
  run_remote "rm -f '${REMOTE_RAW_PATH}'" || true

  if [[ -n ${existing_vmid} ]]; then
    log "VM ${existing_vmid} already exists; updating disk and configuration."
    ensure_vm_stopped "${existing_vmid}"
  else
    log "Creating VM ${vmid} (${CONFIG_VM_NAME})..."
    run_remote "qm create ${vmid} --name ${CONFIG_VM_NAME} --memory ${CONFIG_VM_MEMORY} --cores ${CONFIG_VM_CORES} --sockets 1 --net0 virtio,bridge=${CONFIG_PROXMOX_BRIDGE} --ostype l26 --onboot 1 --scsihw virtio-scsi-pci --boot c"
  fi

  log "Importing CHR disk into storage ${CONFIG_PROXMOX_STORAGE}..."
  run_remote "qm importdisk ${vmid} ${REMOTE_IMAGE_PATH} ${CONFIG_PROXMOX_STORAGE} --format qcow2"

  log "Attaching imported disk and configuring boot order..."
  local disk_ref
  disk_ref=$(run_remote --silent "bash -lc 'qm config ${vmid} | awk -F": " '\''/^unused[0-9]+:/ {print $2}'\'' | tail -n1'") || disk_ref=""
  disk_ref=$(printf '%s' "${disk_ref}" | tr -d '\r')

  if [[ -z ${disk_ref} ]]; then
    disk_ref="${CONFIG_PROXMOX_STORAGE}:vm-${vmid}-disk-0"
  fi

  run_remote "qm set ${vmid} --delete scsi0" || true
  run_remote "qm set ${vmid} --scsihw virtio-scsi-pci --scsi0 ${disk_ref} --boot order=scsi0 --vga std --ide2 none,media=cdrom --agent enabled=1,fstrim_cloned_disks=1"

  log "Removing uploaded image to free space..."
  run_remote "rm -f '${REMOTE_IMAGE_PATH}'" || true

  log "Starting CHR VM..."
  run_remote "qm start ${vmid}" || log "VM already running."

  log "Deployment complete. Access the VM console via Proxmox GUI or 'qm terminal ${vmid}'."

  trap - RETURN
  rm -rf "${work_dir}"

  close_ssh_master
}

prompt_for_value() {
  local var_name="$1"
  local label="$2"
  local validation="${3:-text}"
  local current_value="${!var_name}"
  local input

  while true; do
    read -r -p "${label} [${current_value}]: " input || return
    if [[ -z ${input} ]]; then
      return
    fi

    case ${validation} in
      number)
        if [[ ${input} =~ ^[0-9]+$ ]]; then
          printf -v "${var_name}" '%s' "${input}"
          return
        else
          echo "Please enter a numeric value." >&2
        fi
        ;;
      vmid)
        if [[ ${input} == "auto" || ${input} =~ ^[0-9]+$ ]]; then
          printf -v "${var_name}" '%s' "${input}"
          return
        else
          echo "Enter 'auto' or a numeric VM ID." >&2
        fi
        ;;
      *)
        printf -v "${var_name}" '%s' "${input}"
        return
        ;;
    esac
  done
}

change_configuration() {
  load_config
  ensure_ssh_connection

  local vmid
  vmid=$(lookup_existing_vmid || true)
  if [[ -n ${vmid} ]]; then
    log "Shutting down VM ${vmid} before editing configuration..."
    ensure_vm_stopped "${vmid}"
  else
    log "No existing VM detected; proceeding with configuration update."
  fi

  close_ssh_master

  echo
  echo "Press Enter to keep the current value."

  prompt_for_value CONFIG_PROXMOX_HOST "Proxmox host"
  prompt_for_value CONFIG_PROXMOX_USER "Proxmox user"
  prompt_for_value CONFIG_PROXMOX_NODE "Proxmox node"
  prompt_for_value CONFIG_PROXMOX_BRIDGE "Network bridge"
  prompt_for_value CONFIG_PROXMOX_STORAGE "Storage target"
  prompt_for_value CONFIG_VM_ID "VM ID" vmid
  prompt_for_value CONFIG_VM_NAME "VM name"
  prompt_for_value CONFIG_VM_MEMORY "VM memory (MB)" number
  prompt_for_value CONFIG_VM_CORES "VM CPU cores" number
  prompt_for_value CONFIG_IMAGE_VERSION "CHR version"
  prompt_for_value CONFIG_IMAGE_REMOTEDIR "Remote image directory"

  save_config
  load_config

  log "Configuration updated."
}

destroy_vm() {
  load_config
  ensure_ssh_connection

  local vmid
  vmid=$(lookup_existing_vmid || true)

  if [[ -z ${vmid} ]]; then
    log "No matching VM found to destroy."
    close_ssh_master
    return
  fi

  log "Destroying VM ${vmid} (${CONFIG_VM_NAME})..."
  ensure_vm_stopped "${vmid}"

  log "Ensuring VM ${vmid} is powered off before destruction..."
  run_remote "qm stop ${vmid}" || true

  run_remote "qm destroy ${vmid} --purge" || log "Failed to destroy VM ${vmid}."
  run_remote "rm -f '${REMOTE_IMAGE_PATH}'" || true

  log "VM ${vmid} destroyed."

  close_ssh_master
}

show_menu() {
  while true; do
    load_config
    echo
    echo "=== MikroTik CHR Proxmox Utility ==="
    echo "Target host : ${CONFIG_PROXMOX_USER}@${CONFIG_PROXMOX_HOST}"
    echo "VM name     : ${CONFIG_VM_NAME} (ID: ${CONFIG_VM_ID})"
    echo "Image ver.  : ${CONFIG_IMAGE_VERSION}"
    echo "Storage     : ${CONFIG_PROXMOX_STORAGE} on ${CONFIG_PROXMOX_NODE}"
    echo
    echo "1) Deploy / Update CHR VM"
    echo "2) Destroy CHR VM"
    echo "3) Edit configuration"
    echo "4) Exit"
    echo
    echo "Creative spark, AI prompting, and continuous debugging by: Attila Macskasy"
    echo "Code generated using: GPT-5 Codex (Preview) — Premium Model x1"
    echo
    read -r -p "Select an option [1-4]: " choice || break

    case ${choice} in
      1)
        deploy_vm
        ;;
      2)
        destroy_vm
        ;;
      3)
        change_configuration
        ;;
      4)
        log "Exiting."
        break
        ;;
      *)
        echo "Invalid selection." >&2
        ;;
    esac
  done
}

main() {
  show_menu
}

main "$@"
