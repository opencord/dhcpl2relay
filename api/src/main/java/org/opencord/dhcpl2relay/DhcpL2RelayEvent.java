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

import java.util.concurrent.atomic.AtomicLong;
import java.util.Map;

/**
 * Dhcp L2 relay event.
 */
public class DhcpL2RelayEvent extends AbstractEvent<DhcpL2RelayEvent.Type, DhcpAllocationInfo> {

    private final ConnectPoint connectPoint;

    private final Map<String, AtomicLong> countersMap;

    private final String dhcpCountersTopic;

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
     * Creates a new event.
     *
     * @param type type of the event
     * @param allocationInfo DHCP allocation info
     * @param connectPoint connect point the client is on
     * @param countersMap the map of counters (used for STATS events)
     * @param dhcpCountersTopic Kafka topic where the dhcp counters are published
     * @param subscriberId the subscriber identifier information
     */
    public DhcpL2RelayEvent(Type type, DhcpAllocationInfo allocationInfo, ConnectPoint connectPoint,
                            Map<String, AtomicLong> countersMap,  String dhcpCountersTopic, String subscriberId) {
        super(type, allocationInfo);
        this.connectPoint = connectPoint;
        this.countersMap = countersMap;
        this.dhcpCountersTopic = dhcpCountersTopic;
        this.subscriberId = subscriberId;
    }

    /**
     * Gets the DHCP client connect point.
     *
     * @return connect point
     */
    public ConnectPoint connectPoint() {
        return connectPoint;
    }

    public Map<String, AtomicLong> getCountersMap() {
        return countersMap;
    }

    public String getDhcpCountersTopic() {
        return dhcpCountersTopic;
    }

    public String getSubscriberId() {
        return subscriberId;
    }
}
