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

import org.easymock.EasyMock;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.onlab.junit.TestUtils;
import org.onlab.osgi.ComponentContextAdapter;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.cluster.LeadershipServiceAdapter;
import org.onosproject.net.flowobjective.FlowObjectiveServiceAdapter;
import org.onosproject.store.service.TestStorageService;
import org.opencord.dhcpl2relay.DhcpL2RelayEvent;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertEquals;


public class DhcpL2RelayCountersStoreTest extends DhcpL2RelayTestBase {

    private DhcpL2Relay dhcpL2Relay;
    private SimpleDhcpL2RelayCountersStore store;

    ComponentConfigService mockConfigService =
            EasyMock.createMock(ComponentConfigService.class);

    /**
     * Sets up the services required by the dhcpl2relay app.
     */
    @Before
    public void setUp() {
        dhcpL2Relay = new DhcpL2Relay();
        dhcpL2Relay.cfgService = new DhcpL2RelayConfigTest.TestNetworkConfigRegistry();
        dhcpL2Relay.coreService = new MockCoreServiceAdapter();
        dhcpL2Relay.flowObjectiveService = new FlowObjectiveServiceAdapter();
        dhcpL2Relay.packetService = new MockPacketService();
        dhcpL2Relay.componentConfigService = mockConfigService;
        dhcpL2Relay.deviceService = new MockDeviceService();
        dhcpL2Relay.sadisService = new MockSadisService();
        dhcpL2Relay.mastershipService = new MockMastershipService();
        dhcpL2Relay.storageService = new TestStorageService();
        dhcpL2Relay.leadershipService = new LeadershipServiceAdapter();
        TestUtils.setField(dhcpL2Relay, "eventDispatcher", new TestEventDispatcher());
        dhcpL2Relay.activate(new ComponentContextAdapter());
        store = new SimpleDhcpL2RelayCountersStore();
        TestUtils.setField(store, "eventDispatcher", new TestEventDispatcher());
        store.activate();
        dhcpL2Relay.dhcpL2RelayCounters = this.store;
    }

    /**
     * Tears down the dhcpL2Relay application.
     */
    @After
    public void tearDown() {
        dhcpL2Relay.deactivate();
    }

    /**
     * Tests the initialization of the counter.
     */
    @Test
    public void testInitCounter() {
        // Init the supported global counter
        dhcpL2Relay.dhcpL2RelayCounters.initCounters(DhcpL2RelayEvent.GLOBAL_COUNTER);
        // Init the supported counter for a specific subscriber
        dhcpL2Relay.dhcpL2RelayCounters.initCounters(CLIENT_ID_1);

        Map<DhcpL2RelayCountersIdentifier, AtomicLong> countersMap = dhcpL2Relay.dhcpL2RelayCounters.getCountersMap();
        for (Iterator<DhcpL2RelayCounters> it = DhcpL2RelayCounters.SUPPORTED_COUNTERS.iterator();
             it.hasNext();) {
            DhcpL2RelayCounters counterType = it.next();
            long globalCounterValue = countersMap.get(new DhcpL2RelayCountersIdentifier(
                    DhcpL2RelayEvent.GLOBAL_COUNTER, counterType)).longValue();
            long perSubscriberValue = countersMap.get(new DhcpL2RelayCountersIdentifier(CLIENT_ID_1,
                    counterType)).longValue();
            assertEquals((long) 0, globalCounterValue);
            assertEquals((long) 0, perSubscriberValue);
        }
    }

    /**
     * Tests the insertion of the counter entry if it is not already in the set
     * otherwise increment the existing counter entry.
     */
    @Test
    public void testIncrementCounter() {
        // Init the supported global counter
        dhcpL2Relay.dhcpL2RelayCounters.initCounters(DhcpL2RelayEvent.GLOBAL_COUNTER);

        for (Iterator<DhcpL2RelayCounters> it = DhcpL2RelayCounters.SUPPORTED_COUNTERS.iterator();
             it.hasNext();) {
            DhcpL2RelayCounters counterType = it.next();
            // Increment of existing supported global counter
            dhcpL2Relay.dhcpL2RelayCounters.incrementCounter(DhcpL2RelayEvent.GLOBAL_COUNTER, counterType);
            // Add of a Subscriber entry that is not already in the set
            dhcpL2Relay.dhcpL2RelayCounters.incrementCounter(CLIENT_ID_1, counterType);
        }

        Map<DhcpL2RelayCountersIdentifier, AtomicLong> countersMap = dhcpL2Relay.dhcpL2RelayCounters.getCountersMap();
        for (Iterator<DhcpL2RelayCounters> it = DhcpL2RelayCounters.SUPPORTED_COUNTERS.iterator();
             it.hasNext();) {
            DhcpL2RelayCounters counterType = it.next();
            long globalCounterValue = countersMap.get(new DhcpL2RelayCountersIdentifier(
                    DhcpL2RelayEvent.GLOBAL_COUNTER, counterType)).longValue();
            long perSubscriberValue = countersMap.get(new DhcpL2RelayCountersIdentifier(CLIENT_ID_1,
                    counterType)).longValue();
            assertEquals((long) 1, globalCounterValue);
            assertEquals((long) 1, perSubscriberValue);
        }
    }

    /**
     * Tests the increment and reset functions of the counters map for the given counter class.
     */
    @Test
    public void testIncrementAndResetCounter() {
        DhcpL2RelayCounters counterType;
        long subscriberValue;
        Map<DhcpL2RelayCountersIdentifier, AtomicLong> countersMap;

        // First start incrementing the counter of a specific subscriber
        for (Iterator<DhcpL2RelayCounters> it = DhcpL2RelayCounters.SUPPORTED_COUNTERS.iterator();
             it.hasNext();) {
            counterType = it.next();
            // Insert of a Subscriber entry that is not already in the set
            dhcpL2Relay.dhcpL2RelayCounters.incrementCounter(CLIENT_ID_1, counterType);
        }

        // Make sure that the counter is incremented
        countersMap = dhcpL2Relay.dhcpL2RelayCounters.getCountersMap();
        for (Iterator<DhcpL2RelayCounters> it = DhcpL2RelayCounters.SUPPORTED_COUNTERS.iterator();
             it.hasNext();) {
            counterType = it.next();
            subscriberValue = countersMap.get(new DhcpL2RelayCountersIdentifier(CLIENT_ID_1,
                    counterType)).longValue();
            assertEquals((long) 1, subscriberValue);
        }

        // Reset the counter
        dhcpL2Relay.dhcpL2RelayCounters.resetCounters(CLIENT_ID_1);
        countersMap = dhcpL2Relay.dhcpL2RelayCounters.getCountersMap();
        for (Iterator<DhcpL2RelayCounters> it = DhcpL2RelayCounters.SUPPORTED_COUNTERS.iterator();
             it.hasNext();) {
            counterType = it.next();
            subscriberValue = countersMap.get(new DhcpL2RelayCountersIdentifier(CLIENT_ID_1,
                    counterType)).longValue();
            assertEquals((long) 0, subscriberValue);
        }
    }

    /**
     * Tests the insert of the counter value for a subscriber entry if it is not already in the set
     * otherwise update the existing counter entry.
     */
    @Test
    public void testInsertOrUpdateCounter() {
        dhcpL2Relay.dhcpL2RelayCounters.setCounter(CLIENT_ID_1, DhcpL2RelayCounters.valueOf("DHCPDISCOVER"), (long) 50);

        Map<DhcpL2RelayCountersIdentifier, AtomicLong> countersMap = dhcpL2Relay.dhcpL2RelayCounters.getCountersMap();
        long subscriberValue = countersMap.get(new DhcpL2RelayCountersIdentifier(
                CLIENT_ID_1, DhcpL2RelayCounters.valueOf("DHCPDISCOVER"))).longValue();

        assertEquals((long) 50, subscriberValue);
    }

}