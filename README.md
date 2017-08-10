# ONOS DHCP L2 RELAY Application

The ONOS dhcpl2relay application is a DHCP Relay Agent which does Layer 2 relay.

The DHCP packets sent towards the DHCP Server (DHCP DISCOVER and DHCP REQUEST) are double tagged by this app. It retrieves the tag values to be used from the `Sadis` Service. Similarly it replaces the tags on the packets received from the server (DHCP OFFER and DHCP ACK) with priority tags.

DHCP Option 82 with CircuitId and RemoteId are added to packets sent to the DHCP server and  Option 82 received from the server are removed before relaying back to the client. The CircuitId and Remote Id are retrieved from `Sadis` Service.

# Configuration
```sh
"org.opencord.dhcpl2relay" : {
      "dhcpl2relay" : {
        "dhcpserverConnectPoints" : [ "of:00000000000000b2/2" ]
      }
    }
 ```
 ### Configuration Parameters
##### dhcpServerConnectPoints
Port on the switch through which the DHCP Server is reachable

# Example configuration of Sadis
```sh
   "org.opencord.sadis" : {
      "sadis" : {
        "integration" : {
          "cache" : {
            "enabled" : true,
            "maxsize" : 50,
            "ttl" : "PT1m"
          }
        },
        "entries" : [ {
          "id" : "uni-128", # (This is an entry for a subscriber) Same as the portName of the Port as seen in onos ports command
          "cTag" : 2, # C-tag of the subscriber
          "sTag" : 2, # S-tag of the subscriber
          "nasPortId" : "uni-128"  # NAS Port Id of the subscriber, could be different from the id above
        }, {
          "id" : "1d3eafb52e4e44b08818ab9ebaf7c0d4", # (This is an entry for an OLT device) Same as the serial of the OLT logical device as seen in the onos devices command
          "hardwareIdentifier" : "00:1b:22:00:b1:78", # MAC address to be used for this OLT
          "ipAddress" : "192.168.1.252", # IP address to be used for this OLT
          "nasId" : "B100-NASID" # NAS ID to be used for this OLT
        } ]
      }
    }
 ```

