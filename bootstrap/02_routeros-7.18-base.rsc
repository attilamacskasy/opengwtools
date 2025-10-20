:global action apply

:global routerName opengwtools

:global bridgeIP 172.22.254.254
:global subnet 24

:global dhcpStart 172.22.254.224
:global dhcpEnd 172.22.254.250
:global dhcpNetAddr 172.22.254.0/24
:global dhcpServerDisabled no

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

  :log info "Ensuring interface lists exist.";
  :if ([:len [/interface list find where name="WAN"]] = 0) do={
    /interface list add name=WAN comment="defconf";
  } else={
    :log info "Interface list WAN already present.";
  }
  :if ([:len [/interface list find where name="LAN"]] = 0) do={
    /interface list add name=LAN comment="defconf";
  } else={
    :log info "Interface list LAN already present.";
  }

  :log info "Renaming ethernet interfaces based on defaults.";
  :local wanPrimary "";
  :local lanPrimary "";
  :local lanIndex 1;
  :local singleInterfaceMode 0;
  :foreach ethId in=[/interface ethernet find] do={
    :local defaultName [/interface ethernet get $ethId default-name];
    :if ($defaultName = "") do={
      :set defaultName [/interface ethernet get $ethId name];
    }
    :local currentName [/interface ethernet get $ethId name];
    :local newName $currentName;

    :if ($defaultName = "ether1") do={
      :set newName "ether1-wan1";
      :set wanPrimary $newName;
      :if ($currentName != $newName) do={
        :log info ("Renaming " . $currentName . " to " . $newName . ".");
        /interface set $ethId name=$newName;
      } else={
        :log info ("Interface " . $currentName . " already named.");
      }
      :if ([:len [/interface list member find where list=WAN && interface=$newName]] = 0) do={
        /interface list member add list=WAN interface=$newName comment="defconf";
      }
    } else={
      :set newName ($defaultName . "-lan" . $lanIndex);
      :if ($currentName != $newName) do={
        :log info ("Renaming " . $currentName . " to " . $newName . ".");
        /interface set $ethId name=$newName;
      } else={
        :log info ("Interface " . $currentName . " already named.");
      }
      :if ($lanPrimary = "") do={
        :set lanPrimary $newName;
      }
      :if ([:len [/interface list member find where list=LAN && interface=$newName]] = 0) do={
        /interface list member add list=LAN interface=$newName comment="defconf";
      }
      :set lanIndex ($lanIndex + 1);
    }
  }

  :if (($lanPrimary = "") && ($wanPrimary != "")) do={
    :log warning "Only one Ethernet interface detected; using $wanPrimary for LAN bridge and skipping WAN-specific features.";
    :set lanPrimary $wanPrimary;
    :set singleInterfaceMode 1;
    :foreach memberId in=[/interface list member find where list=WAN && interface=$wanPrimary] do={
      /interface list member remove $memberId;
    }
    :if ([:len [/interface list member find where list=LAN && interface=$wanPrimary]] = 0) do={
      /interface list member add list=LAN interface=$wanPrimary comment="defconf-single";
    }
  }

  :if ($wanPrimary = "") do={
    :log warning "No Ethernet interfaces detected for WAN role.";
  }

  :log info "Ensuring bridge interface exists.";
  :if ([:len [/interface bridge find where name="bridge"]] = 0) do={
    /interface bridge add name=bridge disabled=no auto-mac=yes protocol-mode=rstp comment=defconf;
  } else={
    /interface bridge set bridge disabled=no protocol-mode=rstp comment="defconf";
  }
  :if ([:len [/interface list member find where list=LAN && interface="bridge"]] = 0) do={
    /interface list member add list=LAN interface=bridge comment="defconf";
  }

  :log info "Adding LAN interfaces to the bridge.";
  :local bMACIsSet 0;
  :foreach k in=[/interface find where (name~"-lan" && !(slave=yes) && !(name~"bridge"))] do={
    :local tmpPortName [/interface get $k name];
    :if ($bMACIsSet = 0) do={
      :if ([/interface get $k type] = "ether") do={
        :log info "Setting bridge MAC address";
        /interface bridge set "bridge" auto-mac=no admin-mac=[/interface ethernet get $tmpPortName mac-address];
        :set bMACIsSet 1;
      }
    }
    :if ([:len [/interface bridge port find where interface=$tmpPortName]] = 0) do={
      :log info "Adding interface $tmpPortName to bridge.";
      /interface bridge port add bridge=bridge interface=$tmpPortName comment=defconf;
    } else={
      :log info "Interface $tmpPortName already part of bridge.";
    }
  };

  :if (($singleInterfaceMode = 1) && ($lanPrimary != "")) do={
    :if ($bMACIsSet = 0) do={
      :local lanIfaceId [/interface find where name=$lanPrimary];
      :if ([:len $lanIfaceId] > 0) do={
        :if ([/interface get $lanIfaceId type] = "ether") do={
          :log info "Setting bridge MAC address from $lanPrimary.";
          /interface bridge set "bridge" auto-mac=no admin-mac=[/interface ethernet get $lanPrimary mac-address];
          :set bMACIsSet 1;
        }
      }
    }
    :if ([:len [/interface bridge port find where interface=$lanPrimary]] = 0) do={
      :log info "Adding single-interface $lanPrimary to bridge.";
      /interface bridge port add bridge=bridge interface=$lanPrimary comment="defconf-single";
    }
  }

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
  /ip dhcp-server add name=defconf address-pool="default-dhcp" interface=bridge lease-time=10m disabled=$dhcpServerDisabled;
  /ip dhcp-server network add address=$dhcpNetAddr gateway=$bridgeIP dns-server=$bridgeIP comment="defconf";

  :if (($wanPrimary != "") && ($singleInterfaceMode = 0)) do={
    :log info "Enabling DHCP client on WAN interface.";
    :local dhcpId [/ip dhcp-client find where interface=$wanPrimary];
    :if ([:len $dhcpId] = 0) do={
      /ip dhcp-client add interface=$wanPrimary disabled=no comment="defconf";
    } else={
      /ip dhcp-client set $dhcpId disabled=no;
    }
  } else={
    :log warning "Skipping DHCP client configuration (WAN interface unavailable).";
  }

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
