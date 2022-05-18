# ONOS DHCP L2 RELAY Application

The ONOS dhcpl2relay application is a DHCP Relay Agent which does Layer 2 relay.

The DHCP packets sent towards the DHCP Server (DHCP DISCOVER and DHCP REQUEST) are double tagged by this app. It retrieves the tag values to be used from the `Sadis` Service. Similarly it replaces the tags on the packets received from the server (DHCP OFFER and DHCP ACK) with priority tags.

DHCP Option 82 with CircuitId and RemoteId are added to packets sent to the DHCP server and  Option 82 received from the server are removed before relaying back to the client. The CircuitId and Remote Id are retrieved from `Sadis` Service.

There are two options to packet-in/packet-out to the DHCP Server.
* To use a SDN controlled switch which can connect to the DHCP Server; using the configuration parameter `dhcpserverConnectPoints`
* To use the uplink NNI port of the OLT (from which the DHCP Discover/Request was received) for doing the packet-out/packet-in; using the configuration parameter `useOltUplinkForServerPktInOut`

# Configuration
```sh
"org.opencord.dhcpl2relay" : {
      "dhcpl2relay" : {
        "dhcpServerConnectPoints" : [ "of:00000000000000b2/2" ],
        "useOltUplinkForServerPktInOut" : true
      }
    }
 ```
 ### Configuration Parameters
##### dhcpServerConnectPoints
Port on the switch through which the DHCP Server is reachable
##### useOltUplinkForServerPktInOut
The default value of this parameter is **false**. Only if this parameter is false the dhcpServerConnectPoints parameter is used else not

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

# REST API

Information about the DHCP allocations are available through REST API.

You can query all DHCP allocations using the endpoint "/onos/dhcpl2relay/app/allocations", e.g:
```sh
$ curl -u karaf:karaf 'http://localhost:8181/onos/dhcpl2relay/app/allocations'
```

You can also filter by device-id "/onos/dhcpl2relay/app/allocations/{device-id}", e.g:
```sh
curl -u karaf:karaf 'http://localhost:8181/onos/dhcpl2relay/app/allocations/of%3A00000a0a0a0a0a0a'
```

These commands will output a JSON representation of the allocations, e.g:
```sh
{
  "entries": [
    {
      "subscriberId": "BBSM000a0001-1",
      "connectPoint": "of:00000a0a0a0a0a0a/256",
      "state": "DHCPACK",
      "macAddress": "2E:0A:00:01:00:00",
      "vlanId": 900,
      "circuitId": "BBSM000a0001-1",
      "ipAllocated": "10.1.0.0",
      "allocationTimestamp": "2022-05-25T20:09:28.672454Z"
    }
  ]
}
```
