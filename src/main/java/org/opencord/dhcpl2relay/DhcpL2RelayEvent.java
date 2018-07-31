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

import org.onosproject.event.AbstractEvent;
import org.onosproject.net.ConnectPoint;

/**
 * Dhcp L2 relay event.
 */
public class DhcpL2RelayEvent extends AbstractEvent<DhcpL2RelayEvent.Type, DhcpAllocationInfo> {

    private final ConnectPoint connectPoint;

    /**
     * Type of the event.
     */
    public enum Type {
        /**
         * DHCP lease was updated.
         */
        UPDATED,

        /**
         * DHCP lease was removed.
         */
        REMOVED
    }

    /**
     * Creates a new event.
     *
     * @param type type of the event
     * @param allocationInfo DHCP allocation info
     * @param connectPoint connect point the client is on
     */
    public DhcpL2RelayEvent(Type type, DhcpAllocationInfo allocationInfo, ConnectPoint connectPoint) {
        super(type, allocationInfo);
        this.connectPoint = connectPoint;
    }

    /**
     * Gets the DHCP client connect point.
     *
     * @return connect point
     */
    public ConnectPoint connectPoint() {
        return connectPoint;
    }
}
