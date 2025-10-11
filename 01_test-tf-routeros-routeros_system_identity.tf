terraform {
  required_providers {
    routeros = {
      source  = "terraform-routeros/routeros"
    }
  }
}

provider "routeros" {
  hosturl        = "apis://172.22.24.254:8729"   # env ROS_HOSTURL or MIKROTIK_HOST
  username       = "terraform"                   # env ROS_USERNAME or MIKROTIK_USER
  password       = "setup1setup1"                # env ROS_PASSWORD or MIKROTIK_PASSWORD
  ca_certificate = "${path.module}/certs/terraform-ca.crt"
  insecure       = false
}

# If you only want to retrieve the identity name, this provider does not support it as a data source.
# However, if you want to set the identity name, update your Terraform script as follows:
# Set system identity (name of the router)
resource "routeros_system_identity" "router" {
  name = "petinemvermacskat"  # Change this to the desired router name
}

output "router_identity" {
  value = routeros_system_identity.router.name
}
