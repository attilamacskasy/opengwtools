###########################################################################
# Terraform API bootstrap for MikroTik RouterOS 7                        #
#                                                                         #
# This script creates a dedicated certificate authority, signs server     #
# and client certificates, enables the encrypted API service, and         #
# provisions a Terraform user with API permissions.                       #
#                                                                         #
# Copy the exported files (terraform-ca.crt, terraform-client-key.pem,    #
# terraform-client.crt) from Files after running this script and place    #
# them alongside your Terraform configuration.                            #
#                                                                         #
# Tested with RouterOS v7.18.                                             #
###########################################################################

#### Configuration variables ####
:local terraformCAName       "terraform-ca"
:local terraformServerName   "terraform-api-server"
:local terraformClientName   "terraform-client"
:local terraformUser         "terraform"
:local terraformPassword     "***"
:local certificateCN         "router.local"
:local apiSSLTlsVersion      "only-1.2"

#### Logging prefix ####
:local logId "terraform-api-bootstrap"

:log info "[$logId] Starting Terraform API bootstrap.";

#### Certificate Authority ####
:if ([:len [/certificate find where name=$terraformCAName]] = 0) do={
	:log info "[$logId] Creating CA certificate template.";
	/certificate add name="$terraformCAName-template" common-name=$terraformCAName key-usage=key-cert-sign,crl-sign
	:log info "[$logId] Signing CA certificate.";
	/certificate sign "$terraformCAName-template" name=$terraformCAName;
	/certificate remove "$terraformCAName-template";
} else={
	:log info "[$logId] CA certificate already exists.";
}

#### Server certificate ####
:if ([:len [/certificate find where name=$terraformServerName]] = 0) do={
	:log info "[$logId] Creating server certificate template.";
	/certificate add name="$terraformServerName-template" common-name=$certificateCN subject-alt-name="DNS:$certificateCN" key-usage=digital-signature,key-encipherment,tls-server
	:log info "[$logId] Signing server certificate.";
	/certificate sign "$terraformServerName-template" ca=$terraformCAName name=$terraformServerName;
	/certificate remove "$terraformServerName-template";
} else={
	:log info "[$logId] Server certificate already exists.";
}

#### Client certificate ####
:if ([:len [/certificate find where name=$terraformClientName]] = 0) do={
	:log info "[$logId] Creating client certificate template.";
	/certificate add name="$terraformClientName-template" common-name=$terraformClientName key-usage=digital-signature,key-encipherment,tls-client
	:log info "[$logId] Signing client certificate.";
	/certificate sign "$terraformClientName-template" ca=$terraformCAName name=$terraformClientName;
	/certificate remove "$terraformClientName-template";
} else={
	:log info "[$logId] Client certificate already exists.";
}

#### Trust CA and server certificates ####
/certificate {
	:if ([/certificate get $terraformCAName trusted] = false) do={
		:log info "[$logId] Marking CA certificate as trusted.";
		set $terraformCAName trusted=yes;
	}
	:if ([/certificate get $terraformServerName trusted] = false) do={
		:log info "[$logId] Marking server certificate as trusted.";
		set $terraformServerName trusted=yes;
	}
}

#### Export certificates ####
:log info "[$logId] Exporting CA certificate (PEM).";
/certificate export-certificate $terraformCAName type=PEM file-name=$terraformCAName

:log info "[$logId] Exporting client certificate and key (PEM).";
/certificate export-certificate $terraformClientName type=PEM export-passphrase=$terraformPassword file-name=$terraformClientName

#### Enable encrypted API service ####
:log info "[$logId] Enabling secure API service and disabling plaintext API.";
/ip service {
	set api disabled=yes
	set api-ssl certificate=$terraformServerName disabled=no tls-version=$apiSSLTlsVersion
}

#### REST API (optional) ####
:if ([:len [/ip service find where name="www-ssl" && certificate=$terraformServerName]] = 0) do={
	:log info "[$logId] Binding server certificate to HTTPS service for REST API.";
	/ip service set www-ssl certificate=$terraformServerName disabled=no
}

#### Create Terraform user group ####
:if ([:len [/user group find where name="terraform"]] = 0) do={
	:log info "[$logId] Creating Terraform user group with API access.";
	/user group add name=terraform policy=read,write,api,rest,password,system,test,ftp
}

#### Create Terraform user ####
:if ([:len [/user find where name=$terraformUser]] = 0) do={
	:log info "[$logId] Creating Terraform user.";
	/user add name=$terraformUser password=$terraformPassword group=terraform comment="Terraform automation user"
} else={
	:log info "[$logId] Terraform user already exists; refreshing password.";
	/user set [find where name=$terraformUser] password=$terraformPassword group=terraform
}

:log info "[$logId] Terraform API bootstrap complete. Download exported files from /file.";


