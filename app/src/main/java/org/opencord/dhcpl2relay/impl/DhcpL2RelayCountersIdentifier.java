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

import org.opencord.dhcpl2relay.DhcpL2RelayEvent;

import java.util.Objects;

/**
 * Represents DHCP relay counters identifier.
 */
public final class DhcpL2RelayCountersIdentifier {
    final String counterClassKey;
    final Enum<DhcpL2RelayCounters> counterTypeKey;

    /**
     * Creates a default global counter identifier for a given counterType.
     *
     * @param counterTypeKey Identifies the supported type of DHCP relay counters
     */
    public DhcpL2RelayCountersIdentifier(DhcpL2RelayCounters counterTypeKey) {
        this.counterClassKey = DhcpL2RelayEvent.GLOBAL_COUNTER;
        this.counterTypeKey = counterTypeKey;
    }

    /**
     * Creates a counter identifier. A counter is defined by the key pair &lt;counterClass, counterType&gt;,
     * where counterClass can be maybe global or the subscriber ID and counterType is the supported DHCP message type.
     *
     * @param counterClassKey Identifies which class the counter is assigned (global or per subscriber)
     * @param counterTypeKey Identifies the supported type of DHCP relay counters
     */
    public DhcpL2RelayCountersIdentifier(String counterClassKey, DhcpL2RelayCounters counterTypeKey) {
        this.counterClassKey = counterClassKey;
        this.counterTypeKey = counterTypeKey;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof DhcpL2RelayCountersIdentifier) {
            final DhcpL2RelayCountersIdentifier other = (DhcpL2RelayCountersIdentifier) obj;
            return Objects.equals(this.counterClassKey, other.counterClassKey)
                    && Objects.equals(this.counterTypeKey, other.counterTypeKey);
        }

        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hash(counterClassKey, counterTypeKey);
    }
}