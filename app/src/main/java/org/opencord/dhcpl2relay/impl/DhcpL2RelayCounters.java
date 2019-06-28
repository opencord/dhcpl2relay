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

import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public class DhcpL2RelayCounters {
    // DHCP counters
    static final String DHCPDISCOVER = "DHCPDISCOVER";
    static final String DHCPRELEASE = "DHCPRELEASE";
    static final String DHCPDECLINE = "DHCPDECLINE";
    static final String DHCPREQUEST = "DHCPREQUEST";
    static final String DHCPOFFER = "DHCPOFFER";
    static final String DHCPACK = "DHCPACK";
    static final String DHCPNACK = "DHCPNACK";
    static final String PACKETS_TO_SERVER = "PACKETS_TO_SERVER";
    static final String PACKETS_FROM_SERVER = "PACKETS_FROM_SERVER";

    static final Set<String> SUPPORTED_COUNTERS =
            ImmutableSet.of(DHCPDISCOVER, DHCPRELEASE, DHCPDECLINE, DHCPREQUEST, DHCPOFFER, DHCPACK, DHCPNACK,
                    PACKETS_TO_SERVER, PACKETS_FROM_SERVER);

    private Map<String, AtomicLong> countersMap = new ConcurrentHashMap<>();

    public void initCounters() {
        for (String c : SUPPORTED_COUNTERS) {
            countersMap.put(c, new AtomicLong(0));
        }
    }

    public void resetCounters() {
        countersMap.forEach((name, value) -> {
            countersMap.put(name, new AtomicLong(0));
        });
    }

    public boolean setCounter(String name, Long value) {
        boolean counterValid = false;
        if (SUPPORTED_COUNTERS.contains(name)) {
            AtomicLong counter = countersMap.get(name);
            if (counter != null) {
                counter.set(value);
                countersMap.put(name, counter);
            } else {
                // this is the first time
                countersMap.put(name, new AtomicLong(value));
            }
            counterValid = true;
        }
        return counterValid;
    }

    public boolean incrementCounter(String name) {
        boolean counterValid = false;
        if (SUPPORTED_COUNTERS.contains(name)) {
            AtomicLong counter = countersMap.get(name);
            if (counter != null) {
                counter.incrementAndGet();
                countersMap.put(name, counter);
            } else {
                // this is the first time
                countersMap.put(name, new AtomicLong(1));
            }
            counterValid = true;
        }
        return counterValid;
    }

    public Map<String, AtomicLong> getCounters() {
        return countersMap;
    }

    @Override
    public int hashCode() {
        return Objects.hash(countersMap);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof DhcpL2RelayCounters)) {
            return false;
        }
        DhcpL2RelayCounters that = (DhcpL2RelayCounters) obj;
        return Objects.equals(countersMap, that.countersMap);
    }
}
