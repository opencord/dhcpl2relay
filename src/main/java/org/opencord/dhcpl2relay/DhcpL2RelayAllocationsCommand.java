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
package org.opencord.dhcpl2relay;

import org.apache.karaf.shell.commands.Command;
import org.onosproject.cli.AbstractShellCommand;

/**
 *  Shows the Successful DHCP allocations relayed by the dhcpl2relay.
 */
@Command(scope = "onos", name = "dhcpl2relay-allocations",
        description = "Shows the Successful DHCP allocations relayed by the dhcpl2relay")
public class DhcpL2RelayAllocationsCommand extends AbstractShellCommand {
    @Override
    protected void execute() {
        DhcpL2Relay.allocationMap().forEach((key, value) -> {
            print("SubscriberId=%s,MAC=%s,CircuitId=%s,IP Allocated=%s,Allocation Timestamp=%s",
                    key, value.macAddress().toString(), value.circuitId(),
                    value.ipAddress().getIp4Address().toString(), value.allocationTime().toString());
        });
    }
}
