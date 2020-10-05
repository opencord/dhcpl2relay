/*
 * Copyright 2016-present Open Networking Foundation
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

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.opencord.dhcpl2relay.DhcpL2RelayService;

/**
 *  Shows the Successful DHCP allocations relayed by the dhcpl2relay.
 */
@Service
@Command(scope = "onos", name = "dhcpl2relay-allocations",
        description = "Shows the Successful DHCP allocations relayed by the dhcpl2relay")
public class DhcpL2RelayAllocationsCommand extends AbstractShellCommand {
    @Override
    protected void doExecute() {
        DhcpL2RelayService service = get(DhcpL2RelayService.class);

        service.getAllocationInfo().forEach((key, value) -> {
            print("SubscriberId=%s,ConnectPoint=%s,State=%s,MAC=%s,VLAN=%s,"
                    + "CircuitId=%s,IP Allocated=%s,Allocation Timestamp=%s",
                    value.subscriberId(), value.location(), value.type(),
                    value.macAddress().toString(), value.vlanId().toString(),
                    value.circuitId(), value.ipAddress().getIp4Address().toString(),
                    value.allocationTime().toString());
        });
    }
}
