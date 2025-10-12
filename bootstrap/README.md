# opengwtools

LZ Connectivity - deployment and configuration support for popular gateways.

## Terraform + MikroTik quick start

1. Import `01_routeros-api-create-certificates-for-terraform.rsc` into your RouterOS 7 device and run it once. The script creates trusted certificates, enables the TLS API (`api-ssl`), and provisions a `terraform` user.
2. Download the exported files from `/file` on the router (`terraform-ca.crt`, `terraform-client.crt`, `terraform-client.key.enc`) and copy at least `terraform-ca.crt` into `certs/terraform-ca.crt` within this repository. Keep the client files for mutual TLS if needed.
3. Update `01_test-tf-routeros-routeros_system_identity.tf` with your router address, desired hostname, and credentials or environment variables.
4. Run `terraform init` followed by `terraform apply` to push the RouterOS identity change over the encrypted MikroTik API service.

> Tip: set `ROS_HOSTURL=apis://<router-ip>:8729`, `ROS_USERNAME`, `ROS_PASSWORD`, and `ROS_CA_CERTIFICATE` environment variables instead of hardcoding sensitive data.
