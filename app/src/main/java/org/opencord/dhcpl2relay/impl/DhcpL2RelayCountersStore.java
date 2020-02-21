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

import org.onosproject.store.Store;
import org.opencord.dhcpl2relay.DhcpL2RelayEvent;
import org.opencord.dhcpl2relay.DhcpL2RelayStoreDelegate;

/**
 * Represents a stored DHCP Relay Counters. A counter entry is defined by the pair &lt;counterClass, counterType&gt;,
 * where counterClass can be maybe global or subscriber ID and counterType is the DHCP message type.
 */
public interface DhcpL2RelayCountersStore extends Store<DhcpL2RelayEvent, DhcpL2RelayStoreDelegate> {

    String NAME = "DHCP_L2_Relay_stats";

    /**
     * Creates or updates DHCP L2 Relay counter.
     *
     * @param counterClass class of counters (global, per subscriber).
     * @param counterType name of counter
     */
    void incrementCounter(String counterClass, DhcpL2RelayCounterNames counterType);

    /**
     * Sets the value of a DHCP L2 Relay counter.
     *
     * @param counterClass class of counters (global, per subscriber).
     * @param counterType name of counter
     * @param value The value of the counter
     */
    void setCounter(String counterClass, DhcpL2RelayCounterNames counterType, Long value);

    /**
     * Gets the current DHCP L2 relay counter values.
     *
     * @return DHCP L2 relay counter values
     */
    DhcpL2RelayStatistics getCounters();

    /**
     * Resets counter values for a given counter class.
     *
     * @param counterClass class of counters (global, per subscriber).
     */
    void resetCounters(String counterClass);
}