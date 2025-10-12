:global action apply

:global routerName nemver

:global bridgeIP 172.22.24.254
:global subnet 24

:global dhcpStart 172.22.24.224
:global dhcpEnd 172.22.24.250
:global dhcpNetAddr 172.22.24.0/24

:log info "Starting BASE parameterized configuration script.";

:if ($action = "apply") do={
  :local count 0;
  :log info "Waiting for Ethernet interfaces to be detected.";
  :while ([/interface ethernet find] = "") do={
    :if ($count = 30) do={
    :log warning "No Ethernet interfaces found!";
    /quit;
    }
    :delay 1s; :set count ($count +1); 
  };

  :log info "Setting router identity.";
  /system identity set name=$routerName;

  :log info "Creating interface lists.";
  /interface list add name=WAN comment="defconf";
  /interface list add name=LAN comment="defconf";

  :log info "Renaming ether interfaces.";
  /interface set ether1 name=ether1-wan1;
  :log info "Renamed ether1 to ether1-wan1.";
  /interface set ether2 name=ether2-wan2;
  :log info "Renamed ether2 to ether2-wan2.";
  /interface set ether3 name=ether3-lan1;
  :log info "Renamed ether3 to ether3-lan1.";

  :log info "Creating bridge interface.";
  /interface bridge add name=bridge disabled=no auto-mac=yes protocol-mode=rstp comment=defconf;

  :log info "Assigning interfaces to respective interface lists.";
  /interface list member add list=WAN interface=ether1-wan1 comment="defconf";
  /interface list member add list=WAN interface=ether2-wan2 comment="defconf";
  /interface list member add list=LAN interface=bridge comment="defconf";

  :log info "Adding available interfaces to the bridge (except WAN interfaces).";
  :local bMACIsSet 0;
  :foreach k in=[/interface find where !(slave=yes  || name="ether1-wan1" || name="ether2-wan2" || name~"bridge")] do={
    :local tmpPortName [/interface get $k name];
    :if ($bMACIsSet = 0) do={
      :if ([/interface get $k type] = "ether") do={
        :log info "Setting bridge MAC address";
        /interface bridge set "bridge" auto-mac=no admin-mac=[/interface ethernet get $tmpPortName mac-address];
        :set bMACIsSet 1;
      }
    }
    :log info "Adding interface $tmpPortName to bridge.";
    /interface bridge port add bridge=bridge interface=$tmpPortName comment=defconf;
  };

  :log info "Waiting 10s before setting bridge IP address.";
  :delay 10s;

  :log info "Setting bridge IP address to [$bridgeIP/$subnet].";
  /ip address add address="$bridgeIP/$subnet" interface=bridge comment="defconf";

  :log info "Configuring DNS server.";
  /ip dns {
    set allow-remote-requests=yes;
    static add name=router.lan address=$bridgeIP comment=defconf;
  }

  :log info "Configuring DHCP pool with ranges [$dhcpStart-$dhcpEnd].";
  /ip pool add name="default-dhcp" ranges="$dhcpStart-$dhcpEnd";

  :log info "Configuring DHCP server network address [$dhcpNetAddr].";
  /ip dhcp-server add name=defconf address-pool="default-dhcp" interface=bridge lease-time=10m disabled=no;
  /ip dhcp-server network add address=$dhcpNetAddr gateway=$bridgeIP dns-server=$bridgeIP comment="defconf";

  :log info "Enabling DHCP client on LAN [ether3-lan1] interface.";
  /ip dhcp-client add interface=ether3-lan1 disabled=no comment="defconf";

  :log info "Configuring NAT masquerade.";
  /ip firewall nat add chain=srcnat out-interface-list=WAN ipsec-policy=out,none action=masquerade comment="defconf: masquerade";

  :log info "Configuring firewall rules.";
  /ip firewall {
    filter add chain=input action=accept connection-state=established,related,untracked comment="defconf: accept established, related, untracked";
    filter add chain=input action=drop connection-state=invalid comment="defconf: drop invalid";
    filter add chain=input action=accept protocol=icmp comment="defconf: accept ICMP";
    filter add chain=input action=accept dst-address=127.0.0.1 comment="defconf: accept loopback (for CAPsMAN)";
    filter add chain=input action=drop in-interface-list=!LAN comment="defconf: drop all not from LAN";
    filter add chain=forward action=accept ipsec-policy=in,ipsec comment="defconf: accept inbound IPsec";
    filter add chain=forward action=accept ipsec-policy=out,ipsec comment="defconf: accept outbound IPsec";
    filter add chain=forward action=fasttrack-connection connection-state=established,related comment="defconf: fasttrack";
    filter add chain=forward action=accept connection-state=established,related,untracked comment="defconf: accept established, related, untracked";
    filter add chain=forward action=drop connection-state=invalid comment="defconf: drop invalid";
    filter add chain=forward action=drop connection-state=new connection-nat-state=!dstnat in-interface-list=WAN comment="defconf: drop all from WAN not DSTNATed";
  }

  :log info "Configuring MAC server settings.";
  /ip neighbor discovery-settings set discover-interface-list=LAN;
  /tool mac-server set allowed-interface-list=LAN;
  /tool mac-server mac-winbox set allowed-interface-list=LAN;
}

:log info "Default configuration script finished.";
