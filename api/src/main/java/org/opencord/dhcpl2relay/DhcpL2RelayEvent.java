/*
 * Copyright 2018-2023 Open Networking Foundation (ONF) and the ONF Contributors
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

import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Dhcp L2 relay event.
 */
public class DhcpL2RelayEvent extends AbstractEvent<DhcpL2RelayEvent.Type, DhcpAllocationInfo> {

    public static final String GLOBAL_COUNTER = "global";

    private final ConnectPoint connectPoint;

    private final Map.Entry<String, AtomicLong> countersEntry;

    private final String subscriberId;

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
        REMOVED,

        /**
         * DHCP stats update.
         */
        STATS_UPDATE
    }

    /**
     * Creates a new event used for STATS.
     *
     * @param type type of the event
     * @param allocationInfo DHCP allocation info
     * @param connectPoint connect point the client is on
     * @param countersEntry an entry that represents the counters (used for STATS events)
     * @param subscriberId the subscriber identifier information
     */
    public DhcpL2RelayEvent(Type type, DhcpAllocationInfo allocationInfo, ConnectPoint connectPoint,
                            Map.Entry<String, AtomicLong> countersEntry, String subscriberId) {
        super(type, allocationInfo);
        this.connectPoint = connectPoint;
        this.countersEntry = countersEntry;
        this.subscriberId = subscriberId;
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
        this.countersEntry = null;
        this.subscriberId = null;
    }

    /**
     * Gets the DHCP client connect point.
     *
     * @return connect point
     */
    public ConnectPoint connectPoint() {
        return connectPoint;
    }

    /**
     * Gets the counters map entry.
     *
     * @return counters map entry
     */
    public Map.Entry<String, AtomicLong> getCountersEntry() {
        return countersEntry;
    }

    /**
     * Gets the subscriber identifier information.
     *
     * @return the Id from subscriber
     */
    public String getSubscriberId() {
        return subscriberId;
    }
}
