/*
 * Copyright 2018-present Open Networking Foundation
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

import org.onosproject.event.ListenerService;

import java.util.Map;

/**
 * DHCP L2 relay service.
 */
public interface DhcpL2RelayService extends
        ListenerService<DhcpL2RelayEvent, DhcpL2RelayListener> {

    /**
     * Returns information about DHCP leases that have been allocated.
     *
     * @return map of subscriber ID to DHCP allocation information
     */
    Map<String, DhcpAllocationInfo> getAllocationInfo();
}
