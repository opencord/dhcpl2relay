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
