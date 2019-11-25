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

import com.google.common.collect.ImmutableMap;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.slf4j.Logger;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import static org.slf4j.LoggerFactory.getLogger;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * DHCP Relay Agent Counters Manager Component.
 */
@Component(immediate = true)
@Service
public class SimpleDhcpL2RelayCountersStore implements DhcpL2RelayCountersStore {
    private ApplicationId appId;
    private final Logger log = getLogger(getClass());
    private Map<DhcpL2RelayCountersIdentifier, AtomicLong> countersMap;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Activate
    public void activate() {
        log.info("Activate Dhcp L2 Counters Manager");
        //appId = coreService.getAppId(DhcpL2Relay.DHCP_L2RELAY_APP);
        countersMap = new ConcurrentHashMap();
        // Initialize counter values for the global counters
        initCounters(DhcpL2RelayCountersIdentifier.GLOBAL_COUNTER);
    }

    public ImmutableMap<DhcpL2RelayCountersIdentifier, AtomicLong> getCountersMap() {
        return ImmutableMap.copyOf(countersMap);
    }

    /**
     * Initialize the supported counters map for the given counter class.
     * @param counterClass class of counters (global, per subscriber)
     */
    public void initCounters(String counterClass) {
        checkNotNull(counterClass, "counter class can't be null");
        for (DhcpL2RelayCounters counterType : DhcpL2RelayCounters.SUPPORTED_COUNTERS) {
            countersMap.put(new DhcpL2RelayCountersIdentifier(counterClass, counterType), new AtomicLong(0));
        }
    }

    /**
     * Inserts the counter entry if it is not already in the set otherwise increment the existing counter entry.
     * @param counterClass class of counters (global, per subscriber)
     * @param counterType name of counter
     */
    public void incrementCounter(String counterClass, DhcpL2RelayCounters counterType) {
        checkNotNull(counterClass, "counter class can't be null");
        if (DhcpL2RelayCounters.SUPPORTED_COUNTERS.contains(counterType)) {
            DhcpL2RelayCountersIdentifier counterIdentifier =
                    new DhcpL2RelayCountersIdentifier(counterClass, counterType);
            countersMap.compute(counterIdentifier, (key, counterValue) ->
                (counterValue != null) ? new AtomicLong(counterValue.incrementAndGet()) : new AtomicLong(1)
            );
        } else {
            log.error("Failed to increment counter class {} of type {}", counterClass, counterType);
        }
    }

    /**
     * Reset the counters map for the given counter class.
     * @param counterClass class of counters (global, per subscriber)
     */
    public void resetCounters(String counterClass) {
        checkNotNull(counterClass, "counter class can't be null");
        for (Iterator<DhcpL2RelayCounters> it = DhcpL2RelayCounters.SUPPORTED_COUNTERS.iterator(); it.hasNext();) {
            DhcpL2RelayCounters counterType = it.next();
            DhcpL2RelayCountersIdentifier counterIdentifier =
                    new DhcpL2RelayCountersIdentifier(counterClass, counterType);
            countersMap.computeIfPresent(counterIdentifier, (key, counterValue) ->
                    new AtomicLong(0)
            );
        }
    }

    /**
     * Inserts the counter entry if it is not already in the set otherwise update the existing counter entry.
     * @param counterClass class of counters (global, per subscriber).
     * @param counterType name of counter
     * @param value conter value
     */
    public void setCounter(String counterClass, DhcpL2RelayCounters counterType, Long value) {
        checkNotNull(counterClass, "counter class can't be null");
        if (DhcpL2RelayCounters.SUPPORTED_COUNTERS.contains(counterType)) {
            DhcpL2RelayCountersIdentifier counterIdentifier =
                    new DhcpL2RelayCountersIdentifier(counterClass, counterType);
            countersMap.put(counterIdentifier, new AtomicLong(value));
        } else {
            log.error("Failed to increment counter class {} of type {}", counterClass, counterType);
        }
    }
}
