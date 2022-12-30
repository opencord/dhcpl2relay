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
import org.onosproject.cli.net.PortNumberCompleter;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.opencord.dhcpl2relay.DhcpL2RelayService;

/**
 * Remove all the DHCP allocations relayed by the dhcpl2relay.
 */
@Service
@Command(scope = "onos", name = "dhcpl2relay-remove-allocation",
        description = "Remove the DHCP allocation relayed by the dhcpl2relay")
public class DhcpL2RelayRemoveAllocationsCommand extends AbstractShellCommand {

    @Argument(index = 0, name = "deviceId", description = "Device ID",
            required = true, multiValued = false)
    @Completion(DeviceIdCompleter.class)
    private String strDeviceId = null;

    @Argument(index = 1, name = "port", description = "Port number",
            required = true, multiValued = false)
    @Completion(PortNumberCompleter.class)
    private String strPort = null;

    @Override
    protected void doExecute() {
        DhcpL2RelayService service = get(DhcpL2RelayService.class);

        DeviceId deviceId = DeviceId.deviceId(strDeviceId);
        PortNumber port = PortNumber.portNumber(strPort);
        ConnectPoint cp = new ConnectPoint(deviceId, port);

        Boolean success = service.removeAllocationsByConnectPoint(cp);

        if (success) {
            print("DHCP Allocation(s) removed for port %s on device %s", strPort, strDeviceId);
        } else {
            print("DHCP Allocation(s) not found for port %s on device %s", strPort, strDeviceId);
        }

    }
}
