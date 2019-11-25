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

/**
 * Represents DHCP relay counters type.
 */
public enum DhcpL2RelayCounters {
    /**
     *  DHCP relay counter of type Discover.
     */
    DHCPDISCOVER,
    /**
     *  DHCP relay counter of type Release.
     */
    DHCPRELEASE,
    /**
     *  DHCP relay counter of type Decline.
     */
    DHCPDECLINE,
    /**
     *  DHCP relay counter of type Request.
     */
    DHCPREQUEST,
    /**
     *  DHCP relay counter of type Offer.
     */
    DHCPOFFER,
    /**
     *  DHCP relay counter of type ACK.
     */
    DHCPACK,
    /**
     *  DHCP relay counter of type NACK.
     */
    DHCPNACK,
    /**
     *  DHCP relay counter of type Packets_to_server.
     */
    PACKETS_TO_SERVER,
    /**
     *  DHCP relay counter of type Packets_from_server.
     */
    PACKETS_FROM_SERVER;

    /**
     * Supported types of DHCP relay counters.
     */
    static final Set<DhcpL2RelayCounters> SUPPORTED_COUNTERS = ImmutableSet.of(DhcpL2RelayCounters.DHCPDISCOVER,
            DhcpL2RelayCounters.DHCPRELEASE, DhcpL2RelayCounters.DHCPDECLINE,
            DhcpL2RelayCounters.DHCPREQUEST, DhcpL2RelayCounters.DHCPOFFER,
            DhcpL2RelayCounters.DHCPACK, DhcpL2RelayCounters.DHCPNACK,
            DhcpL2RelayCounters.PACKETS_TO_SERVER,
            DhcpL2RelayCounters.PACKETS_FROM_SERVER);
    }