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

import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;

import java.util.Date;

/**
 * Information about successful DHCP Allocations.
 */
public class DhcpAllocationInfo {

    private String circuitId;
    private MacAddress macAddress;
    private IpAddress ip;
    private Date allocationTime;

    public DhcpAllocationInfo(String circuitId, MacAddress macAddress, IpAddress ip) {
        this.circuitId = circuitId;
        this.macAddress = macAddress;
        this.ip = ip;
        this.allocationTime = new Date();
    }

    public String circuitId() {
        return circuitId;
    }

    public  MacAddress macAddress() {
        return  macAddress;
    }

    public IpAddress ipAddress() {
        return ip;
    }

    public Date allocationTime() {
        return allocationTime;
    }
}
