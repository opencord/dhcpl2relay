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

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.slf4j.Logger;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.slf4j.LoggerFactory.getLogger;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * DHCP Relay Agent Counters Manager Component.
 */
@Component(immediate = true)
@Service
public class DhcpL2RelayCountersManager implements DhcpL2RelayCountersSet {
    private ApplicationId appId;
    private final Logger log = getLogger(getClass());
    //private DhcpL2RelayCounters dhcpCounters;
    private Map<DhcpL2RelayCountersIdentifier, AtomicLong> countersMap =
            new HashMap<DhcpL2RelayCountersIdentifier, AtomicLong>();

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Activate
    public void activate() {
        log.info("Activate Dhcp L2 Counters Manager");
        appId = coreService.getAppId(DhcpL2Relay.DHCP_L2RELAY_APP);
        //dhcpCounters = new DhcpL2RelayCounters();
        // Initialize the global counters
        initCounters(DhcpL2Relay.GLOBAL_COUNTER);
    }

    public Map<DhcpL2RelayCountersIdentifier, AtomicLong> getCountersMap() {
        return countersMap;
    }

    public void initCounters(String counterClass) {
        checkNotNull(counterClass, "counter class can't be null");
        for (String counterType : DhcpL2RelayCounters.SUPPORTED_COUNTERS) {
            countersMap.put(new DhcpL2RelayCountersIdentifier(counterClass, counterType), new AtomicLong(0));
        }
    }

    public void incrementCounter(String counterClass, String counterType) {
        checkNotNull(counterClass, "counter class can't be null");
        if (DhcpL2RelayCounters.SUPPORTED_COUNTERS.contains(counterType)) {
            DhcpL2RelayCountersIdentifier counterIdentifier =
                    new DhcpL2RelayCountersIdentifier(counterClass, counterType);
            AtomicLong counterValue = countersMap.get(counterIdentifier);
            if (counterValue != null) {
                counterValue.incrementAndGet();
                countersMap.put(counterIdentifier, counterValue);
            } else {
                // this is the first time
                countersMap.put(counterIdentifier, new AtomicLong(1));
            }
        } else {
            log.error("Failed to increment counter class {} of type {}", counterClass, counterType);
        }
    }

    public void resetCounters(String counterClass) {
        checkNotNull(counterClass, "counter class can't be null");
        countersMap.forEach((counterIdentifier, counterValue) -> {
            if (counterIdentifier.counterClassKey.equals(counterClass)) {
                countersMap.put(counterIdentifier, new AtomicLong(0));
            }
        });
    }

    public void setCounter(String counterClass, String counterType, Long value) {
        checkNotNull(counterClass, "counter class can't be null");
        if (DhcpL2RelayCounters.SUPPORTED_COUNTERS.contains(counterType)) {
            DhcpL2RelayCountersIdentifier counterIdentifier =
                    new DhcpL2RelayCountersIdentifier(counterClass, counterType);
            AtomicLong counterValue = countersMap.get(counterIdentifier);
            if (counterValue != null) {
                counterValue.set(value);
                countersMap.put(counterIdentifier, counterValue);
            } else {
                // this is the first time
                countersMap.put(counterIdentifier, new AtomicLong(value));
            }
        } else {
            log.error("Failed to increment counter class {} of type {}", counterClass, counterType);
        }
    }
}
