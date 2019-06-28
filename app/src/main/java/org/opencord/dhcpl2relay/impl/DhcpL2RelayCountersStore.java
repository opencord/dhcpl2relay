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
import java.util.Optional;
import java.util.Set;

/**
 * Stores DHCP Relay Counters records.
 */
public interface DhcpL2RelayCountersStore {

    String NAME = "DHCP_L2_Relay_stats";

    /**
     * Creates or updates DHCP L2 Relay counter.
     *
     * @param counterClass class of counters (global, ...). Only global counters will be implemented for now.
     * @param counterName name of counter
     */
    void incrementCounter(String counterClass, String counterName);

    /**
     * Sets the value of a DHCP L2 Relay counter.
     *
     * @param counterClass class of counters (global, ...). Only global counters will be implemented for now.
     * @param counterName name of counter
     * @param value The value of the counter
     */
    void setCounter(String counterClass, String counterName, Long value);

    /**
     * Gets the DHCP L2 Relay counters records for a given counter class.
     *
     * @param counterClass the class of counters (global, ...)
     * @return the DHCP counter records for a given counter class; empty if record does not exist
     */
    Optional<DhcpL2RelayCounters> getCounters(String counterClass);

    /**
     * Gets all the DHCP L2 Relay counters for all classes from store.
     *
     * @return all classes of DHCP counters records from store
     */
    Set<Map.Entry<String, DhcpL2RelayCounters>> getAllCounters();

    /**
     * Resets counter value for a given counter class.
     *
     * @param counterClass the class of counters
     */
    void resetCounters(String counterClass);

    /**
     * Resets counter value for all counter classes.
     *
     */
    void resetAllCounters();

}
