#!/usr/bin/env bash

# Deploy a MikroTik Cloud Hosted Router (CHR) VM on a remote Proxmox VE server.
# Requirements:
#   - bash >= 4, curl, ssh, scp present on localhost
#   - SSH key-based access to the Proxmox server with privileges to run `qm`
#   - Proxmox VE 7+ on the remote host
#
# Configuration is supplied through environment variables; see the defaults
# below. The script intentionally exits on first error.

set -euo pipefail

###########################
# Configuration defaults  #
###########################

# Remote Proxmox connection parameters
: "${PROXMOX_HOST:?Set PROXMOX_HOST to the Proxmox hostname or IP}"
: "${PROXMOX_USER:=root}"
: "${PROXMOX_NODE:=${PROXMOX_HOST}}"

# VM settings
: "${PROXMOX_VMID:=997}"
: "${PROXMOX_VMNAME:=chr-terraform-lab}"
: "${PROXMOX_BRIDGE:=vmbr0}"
: "${PROXMOX_STORAGE:=local-lvm}"
: "${PROXMOX_MEMORY:=512}"
: "${PROXMOX_CORES:=1}"

# MikroTik CHR image settings
: "${CHR_VERSION:=7.18.1}"  # adjust to tested version
CHR_IMAGE="chr-${CHR_VERSION}.qcow2"
CHR_DOWNLOAD_URL="https://download.mikrotik.com/routeros/${CHR_VERSION}/${CHR_IMAGE}"
REMOTE_IMAGE_DIR="/var/lib/vz/template/qcow2"
REMOTE_IMAGE_PATH="${REMOTE_IMAGE_DIR}/${CHR_IMAGE}"

SSH_TARGET="${PROXMOX_USER}@${PROXMOX_HOST}"
SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new)

####################################
# Helper functions                 #
####################################

log() {
  printf '[deploy-chr] %s\n' "$*"
}

run_remote() {
  ssh "${SSH_OPTS[@]}" "${SSH_TARGET}" "$@"
}

scp_to_remote() {
  scp "${SSH_OPTS[@]}" "$1" "${SSH_TARGET}:$2"
}

ensure_remote_dir() {
  run_remote "sudo mkdir -p '$1' && sudo chown ${PROXMOX_USER}:${PROXMOX_USER} '$1'"
}

####################################
# Download CHR image locally       #
####################################

TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

log "Downloading MikroTik CHR ${CHR_VERSION} image..."
curl -fsSL "${CHR_DOWNLOAD_URL}" -o "${TMP_DIR}/${CHR_IMAGE}"

####################################
# Transfer image to Proxmox host   #
####################################

log "Ensuring remote image directory exists..."
ensure_remote_dir "${REMOTE_IMAGE_DIR}"

log "Uploading image to Proxmox host..."
scp_to_remote "${TMP_DIR}/${CHR_IMAGE}" "${REMOTE_IMAGE_PATH}"

####################################
# Create or update CHR VM          #
####################################

log "Preparing VM ${PROXMOX_VMID} (${PROXMOX_VMNAME}) on node ${PROXMOX_NODE}..."

run_remote "sudo qm status ${PROXMOX_VMID}" >/dev/null 2>&1 && VM_EXISTS=1 || VM_EXISTS=0

if [[ ${VM_EXISTS} -eq 0 ]]; then
  log "Creating VM..."
  run_remote "sudo qm create ${PROXMOX_VMID} \ 
    --name ${PROXMOX_VMNAME} \ 
    --memory ${PROXMOX_MEMORY} \ 
    --cores ${PROXMOX_CORES} \ 
    --net0 virtio,bridge=${PROXMOX_BRIDGE} \ 
    --serial0 socket \ 
    --agent enabled=1,fstrim_cloned_disks=1 \ 
    --ostype l26 \ 
    --onboot 1 \ 
    --scsihw virtio-scsi-pci"
else
  log "VM already exists; disk will be re-imported and configuration refreshed."
fi

log "Importing CHR disk into Proxmox storage ${PROXMOX_STORAGE}..."
run_remote "sudo qm importdisk ${PROXMOX_VMID} ${REMOTE_IMAGE_PATH} ${PROXMOX_STORAGE} --format qcow2"

log "Attaching disk and configuring boot order..."
run_remote "sudo qm set ${PROXMOX_VMID} --scsihw virtio-scsi-pci --scsi0 ${PROXMOX_STORAGE}:vm-${PROXMOX_VMID}-disk-0 --boot order=scsi0"

log "Enabling serial console (required for CHR headless access)..."
run_remote "sudo qm set ${PROXMOX_VMID} --serial0 socket --vga serial0"

log "Setting cloud-init to disabled for clarity..."
run_remote "sudo qm set ${PROXMOX_VMID} --ide2 none,media=cdrom --cipassword '' --ciuser ''" || true

log "Starting CHR VM..."
run_remote "sudo qm start ${PROXMOX_VMID}" || log "VM already running."

log "Deployment complete. Access the CHR console via 'qm terminal ${PROXMOX_VMID}' or SSH once configured."
