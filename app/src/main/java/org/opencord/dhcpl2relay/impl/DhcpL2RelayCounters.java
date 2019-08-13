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
 *
 */
package org.opencord.dhcpl2relay.impl;

import com.google.common.collect.ImmutableSet;

import java.util.Set;

final class DhcpL2RelayCounters {
    private DhcpL2RelayCounters() {
        throw new IllegalStateException("Utility class");
    }

    // DHCP counters
    public enum CounterType {
        DHCPDISCOVER("DHCPDISCOVER"),
        DHCPRELEASE("DHCPRELEASE"),
        DHCPDECLINE("DHCPDECLINE"),
        DHCPREQUEST("DHCPREQUEST"),
        DHCPOFFER("DHCPOFFER"),
        DHCPACK("DHCPACK"),
        DHCPNACK("DHCPNACK"),
        PACKETS_TO_SERVER("PACKETS_TO_SERVER"),
        PACKETS_FROM_SERVER("PACKETS_FROM_SERVER");

        private String counterType;

        public String getCounterType() {
            return this.counterType;
        }

        CounterType(String counterType) {
            this.counterType = counterType;
        }
    }

    static final Set<String> SUPPORTED_COUNTERS =
            ImmutableSet.of(CounterType.DHCPDISCOVER.toString(), CounterType.DHCPRELEASE.toString(),
                    CounterType.DHCPDECLINE.toString(), CounterType.DHCPREQUEST.toString(),
                    CounterType.DHCPOFFER.toString(), CounterType.DHCPACK.toString(), CounterType.DHCPNACK.toString(),
                    CounterType.PACKETS_TO_SERVER.toString(), CounterType.PACKETS_FROM_SERVER.toString());
}
