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
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;

import org.onlab.util.KryoNamespace;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.store.serializers.KryoNamespaces;
import org.onosproject.store.service.ConsistentMap;
import org.onosproject.store.service.Serializer;
import org.onosproject.store.service.StorageService;
import org.onosproject.store.service.Versioned;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static com.google.common.base.Preconditions.checkNotNull;

@Component(immediate = true)
@Service
public class DistributedDhcpL2RelayCountersStore implements DhcpL2RelayCountersStore {
    private static final KryoNamespace.Builder APP_KYRO = KryoNamespace.newBuilder()
            .register(KryoNamespaces.API)
            .register(DhcpL2RelayCounters.class);

    private Logger log = LoggerFactory.getLogger(getClass());
    private ConsistentMap<String, DhcpL2RelayCounters> counters;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected StorageService storageService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;


    @Activate
    protected void activated() {
        ApplicationId appId = coreService.getAppId(DhcpL2Relay.DHCP_L2RELAY_APP);
        counters = storageService.<String, DhcpL2RelayCounters>consistentMapBuilder()
                .withSerializer(Serializer.using(APP_KYRO.build()))
                .withName(NAME)
                .withApplicationId(appId)
                .withPurgeOnUninstall()
                .build();

        // Init "global" counters
        DhcpL2RelayCounters countersRecord = getCountersRecord(DhcpL2Relay.GLOBAL_COUNTER);
        countersRecord.initCounters();
        counters.put(DhcpL2Relay.GLOBAL_COUNTER, countersRecord);

        log.info("Counters Store activated");
    }

    @Deactivate
    protected void deactivated() {
        counters.destroy().join();
    }

    private DhcpL2RelayCounters getCountersRecord(String counterClass) {
        Versioned<DhcpL2RelayCounters> vCounters = counters.get(counterClass);
        if (vCounters == null) {
            return (new DhcpL2RelayCounters());
        } else {
            return (vCounters.value());
        }
    }

    @Override
    public void incrementCounter(String counterClass, String counterName) {
        DhcpL2RelayCounters countersRecord = getCountersRecord(counterClass);
        if (!countersRecord.incrementCounter(counterName)) {
            log.error("Failed to increment counter: {}", counterName);
        }
        counters.put(counterClass, countersRecord);
    }

    @Override
    public void setCounter(String counterClass, String counterName, Long value) {
        DhcpL2RelayCounters countersRecord = getCountersRecord(counterClass);
        if (!countersRecord.setCounter(counterName, value)) {
            log.error("Failed to set counter: {} = {}", counterName, value);
        }
        counters.put(counterClass, countersRecord);
    }

    @Override
    public Set<Map.Entry<String, DhcpL2RelayCounters>> getAllCounters() {
        final Set<Map.Entry<String, DhcpL2RelayCounters>> result =
                new HashSet<Map.Entry<String, DhcpL2RelayCounters>>();
        Set<Map.Entry<String, Versioned<DhcpL2RelayCounters>>> tmpCounters = counters.entrySet();
        tmpCounters.forEach(entry -> {
            String key = entry.getKey();
            DhcpL2RelayCounters value = entry.getValue().value();
            ConcurrentHashMap<String, DhcpL2RelayCounters> newMap = new ConcurrentHashMap();
            newMap.put(key, value);

            result.addAll(newMap.entrySet());

        });
        return  result;
    }

    @Override
    public Optional<DhcpL2RelayCounters> getCounters(String counterClass) {
        checkNotNull(counterClass, "counter class can't be null");
        Versioned<DhcpL2RelayCounters> vCounters = counters.get(counterClass);
        if (vCounters == null) {
            return Optional.empty();
        }
        return Optional.of(vCounters.value());
    }

    @Override
    public void resetAllCounters() {
        counters.clear();
    }

    @Override
    public void resetCounters(String counterClass) {
        checkNotNull(counterClass, "counter class can't be null");
        DhcpL2RelayCounters countersRecord = getCountersRecord(counterClass);
        countersRecord.resetCounters();
        counters.put(counterClass, countersRecord);
    }

}
