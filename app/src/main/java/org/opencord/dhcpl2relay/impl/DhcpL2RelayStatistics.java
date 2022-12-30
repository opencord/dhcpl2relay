/*
 * Copyright 2020-2023 Open Networking Foundation (ONF) and the ONF Contributors
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
 */

package org.opencord.dhcpl2relay.impl;

import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Sets;

import java.util.Map;
import java.util.Set;

/**
 * Snapshot of DHCP L2 Relay statistics.
 */
public class DhcpL2RelayStatistics {

    private final ImmutableMap<DhcpL2RelayCountersIdentifier, Long> counters;

    private DhcpL2RelayStatistics(ImmutableMap<DhcpL2RelayCountersIdentifier, Long> counters) {
        this.counters = counters;
    }

    /**
     * Creates a new empty statistics instance.
     */
    public DhcpL2RelayStatistics() {
        counters = ImmutableMap.of();
    }

    /**
     * Gets the value of the counter with the given ID. Defaults to 0 if counter is not present.
     *
     * @param id counter ID
     * @return counter value
     */
    public long get(DhcpL2RelayCountersIdentifier id) {
        return counters.getOrDefault(id, 0L);
    }

    /**
     * Gets the map of counters.
     *
     * @return map of counters
     */
    public Map<DhcpL2RelayCountersIdentifier, Long> counters() {
        return counters;
    }

    /**
     * Creates a new statistics instance with the given counter values.
     *
     * @param counters counters
     * @return statistics
     */
    public static DhcpL2RelayStatistics withCounters(Map<DhcpL2RelayCountersIdentifier, Long> counters) {
        ImmutableMap.Builder<DhcpL2RelayCountersIdentifier, Long> builder = ImmutableMap.builder();

        counters.forEach(builder::put);

        return new DhcpL2RelayStatistics(builder.build());
    }

    /**
     * Adds the given statistics instance to this one (sums the common counters) and returns
     * a new instance containing the result.
     *
     * @param other other instance
     * @return result
     */
    public DhcpL2RelayStatistics add(DhcpL2RelayStatistics other) {
        ImmutableMap.Builder<DhcpL2RelayCountersIdentifier, Long> builder = ImmutableMap.builder();

        Set<DhcpL2RelayCountersIdentifier> keys = Sets.newHashSet(other.counters.keySet());

        counters.forEach((id, value) -> {
            builder.put(id, value + other.counters.getOrDefault(id, 0L));
            keys.remove(id);
        });

        keys.forEach(i -> builder.put(i, other.counters.get(i)));

        return new DhcpL2RelayStatistics(builder.build());
    }

    @Override
    public String toString() {
        MoreObjects.ToStringHelper helper = MoreObjects.toStringHelper(this.getClass());
        counters.forEach((id, v) -> helper.add(id.toString(), v));
        return helper.toString();
    }
}
