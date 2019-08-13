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
 * Represents a stored DHCP Relay Counters.
 */
public interface DhcpL2RelayCountersSet {

    String NAME = "DHCP_L2_Relay_stats";

    /**
     * Inits counter value for a given counter class.
     *
     * @param counterClass the class of counters
     */
    void initCounters(String counterClass);

    /**
     * Creates or updates DHCP L2 Relay counter.
     *
     * @param counterClass class of counters (global, ...). Only global counters will be implemented for now.
     * @param counterType name of counter
     */
    void incrementCounter(String counterClass, String counterType);

    /**
     * Sets the value of a DHCP L2 Relay counter.
     *
     * @param counterClass class of counters (global, ...). Only global counters will be implemented for now.
     * @param counterType name of counter
     * @param value The value of the counter
     */
    void setCounter(String counterClass, String counterType, Long value);

    /**
     * Gets the DHCP L2 Relay counters map.
     *
     * @return the DHCP counter map
     */
    public Map<DhcpL2RelayCountersIdentifier, AtomicLong> getCountersMap();

    /**
     * Resets counter value for a given counter class.
     *
     * @param counterClass the class of counters
     */
    void resetCounters(String counterClass);
}