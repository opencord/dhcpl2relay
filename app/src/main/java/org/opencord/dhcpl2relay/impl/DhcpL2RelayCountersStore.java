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

package org.opencord.dhcpl2relay.impl;

import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Represents a stored DHCP Relay Counters. A counter entry is defined by the pair <counterClass, counterType>,
 * where counterClass can be maybe global or subscriber ID and counterType is the DHCP message type.
 */
public interface DhcpL2RelayCountersStore {

    String NAME = "DHCP_L2_Relay_stats";

    /**
     * Init counter values for a given counter class.
     *
     * @param counterClass class of counters (global, per subscriber).
     */
    void initCounters(String counterClass);

    /**
     * Creates or updates DHCP L2 Relay counter.
     *
     * @param counterClass class of counters (global, per subscriber).
     * @param counterType name of counter
     */
    void incrementCounter(String counterClass, DhcpL2RelayCounters counterType);

    /**
     * Sets the value of a DHCP L2 Relay counter.
     *
     * @param counterClass class of counters (global, per subscriber).
     * @param counterType name of counter
     * @param value The value of the counter
     */
    void setCounter(String counterClass, DhcpL2RelayCounters counterType, Long value);

    /**
     * Gets the DHCP L2 Relay counters map.
     *
     * @return the DHCP counter map
     */
    public Map<DhcpL2RelayCountersIdentifier, AtomicLong> getCountersMap();

    /**
     * Resets counter values for a given counter class.
     *
     * @param counterClass class of counters (global, per subscriber).
     */
    void resetCounters(String counterClass);
}