/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.opencord.dhcpl2relay;

import org.onlab.packet.DHCP;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onosproject.net.ConnectPoint;

import java.time.Instant;

/**
 * Information about DHCP Allocations.
 */
public class DhcpAllocationInfo {

    private ConnectPoint location;
    private String circuitId;
    private MacAddress macAddress;
    private IpAddress ip;
    private Instant allocationTime;
    private DHCP.MsgType type;

    /**
     * Creates a new DHCP allocation info record.
     *
     * @param location connect point the requestor was seen on
     * @param type last known message type
     * @param circuitId option 82 information
     * @param macAddress MAC address of client
     * @param ip IP of client if allocated
     */
    public DhcpAllocationInfo(ConnectPoint location, DHCP.MsgType type,
                              String circuitId, MacAddress macAddress, IpAddress ip) {
        this.location = location;
        this.type = type;
        this.circuitId = circuitId;
        this.macAddress = macAddress;
        this.ip = ip;
        this.allocationTime = Instant.now();
    }

    /**
     * Location the requestor was seen on.
     *
     * @return connect point
     */
    public ConnectPoint location() {
        return location;
    }

    /**
     * Last seen message type of the DHCP exchange.
     *
     * @return DHCP message type
     */
    public DHCP.MsgType type() {
        return type;
    }

    /**
     * Option 82 information.
     *
     * @return circuit ID
     */
    public String circuitId() {
        return circuitId;
    }

    /**
     * MAC address of client.
     *
     * @return mac address
     */
    public  MacAddress macAddress() {
        return  macAddress;
    }

    /**
     * IP address of client if it has one.
     *
     * @return client IP
     */
    public IpAddress ipAddress() {
        return ip;
    }

    /**
     * Timestamp when the last DHCP message was seen.
     *
     * @return time
     */
    public Instant allocationTime() {
        return allocationTime;
    }
}
