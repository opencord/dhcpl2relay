/*
 * Copyright 2016-2023 Open Networking Foundation (ONF) and the ONF Contributors
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
package org.opencord.dhcpl2relay.cli;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.cli.net.DeviceIdCompleter;
import org.onosproject.net.DeviceId;
import org.opencord.dhcpl2relay.DhcpAllocationInfo;
import org.opencord.dhcpl2relay.DhcpL2RelayService;

import java.util.Map;
import java.util.stream.Collectors;

/**
 *  Shows the Successful DHCP allocations relayed by the dhcpl2relay.
 */
@Service
@Command(scope = "onos", name = "dhcpl2relay-allocations",
        description = "Shows the Successful DHCP allocations relayed by the dhcpl2relay")
public class DhcpL2RelayAllocationsCommand extends AbstractShellCommand {

    @Argument(index = 0, name = "deviceId", description = "Access device ID")
    @Completion(DeviceIdCompleter.class)
    private String strDeviceId = null;

    @Override
    protected void doExecute() {
        DhcpL2RelayService service = get(DhcpL2RelayService.class);

        Map<String, DhcpAllocationInfo> allocations = service.getAllocationInfo();

        if (strDeviceId != null && !strDeviceId.isEmpty()) {
            DeviceId deviceId = DeviceId.deviceId(strDeviceId);
            allocations = allocations.entrySet().stream()
                    .filter(a -> a.getValue().location().deviceId().equals(deviceId))
                    .collect(Collectors.toMap(map -> map.getKey(), map -> map.getValue()));
        }

        allocations.forEach((key, value) -> {
            print("SubscriberId=%s,ConnectPoint=%s,State=%s,MAC=%s,VLAN=%s,"
                    + "CircuitId=%s,IP Allocated=%s,Allocation Timestamp=%s",
                    value.subscriberId(), value.location(), value.type(),
                    value.macAddress().toString(), value.vlanId().toString(),
                    value.circuitId(), value.ipAddress().getIp4Address().toString(),
                    value.allocationTime().toString());
        });
    }
}
