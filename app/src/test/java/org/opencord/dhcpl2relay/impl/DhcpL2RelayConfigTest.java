/*
 * Copyright 2017-2023 Open Networking Foundation (ONF) and the ONF Contributors
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

import com.google.common.collect.ImmutableSet;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.onlab.junit.TestUtils;
import org.onlab.osgi.ComponentContextAdapter;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.cluster.LeadershipServiceAdapter;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.config.Config;
import org.onosproject.net.config.NetworkConfigRegistryAdapter;
import org.onosproject.net.flowobjective.FlowObjectiveServiceAdapter;
import org.onosproject.store.service.TestStorageService;

import java.util.Set;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

/**
 * Tests for DHCP relay app configuration.
 */
public class DhcpL2RelayConfigTest extends DhcpL2RelayTestBase {

    static final boolean USE_OLT_ULPORT_FOR_PKT_INOUT = true;
    static final boolean MODIFY_SRC_DST_MAC = true;

    private DhcpL2Relay dhcpL2Relay;

    ComponentConfigService mockConfigService =
            EasyMock.createMock(ComponentConfigService.class);

    /**
     * Sets up the services required by the dhcpl2relay app.
     */
    @Before
    public void setUp() {
        dhcpL2Relay = new DhcpL2Relay();
        dhcpL2Relay.cfgService = new TestNetworkConfigRegistry();
        dhcpL2Relay.coreService = new MockCoreServiceAdapter();
        dhcpL2Relay.flowObjectiveService = new FlowObjectiveServiceAdapter();
        dhcpL2Relay.packetService = new MockPacketService();
        dhcpL2Relay.componentConfigService = mockConfigService;
        dhcpL2Relay.deviceService = new MockDeviceService();
        dhcpL2Relay.sadisService = new MockSadisService();
        dhcpL2Relay.hostService = new MockHostService();
        dhcpL2Relay.mastershipService = new MockMastershipService();
        dhcpL2Relay.storageService = new TestStorageService();
        dhcpL2Relay.leadershipService = new LeadershipServiceAdapter();
        SimpleDhcpL2RelayCountersStore store = new SimpleDhcpL2RelayCountersStore();
        store.componentConfigService = mockConfigService;
        dhcpL2Relay.dhcpL2RelayCounters = store;
        TestUtils.setField(dhcpL2Relay, "eventDispatcher", new TestEventDispatcher());
        dhcpL2Relay.activate(new ComponentContextAdapter());
    }

    /**
     * Mocks the network config registry.
     */
    static class MockDhcpL2RelayConfig extends DhcpL2RelayConfig {
        @Override
        public Set<ConnectPoint> getDhcpServerConnectPoint() {
            return ImmutableSet.of(SERVER_CONNECT_POINT);
        }

        @Override
        public boolean getModifySrcDstMacAddresses() {
            return true;
        }

        @Override
        public boolean getUseOltUplinkForServerPktInOut() {
            return true;
        }
    }

    /**
     * Tests the default configuration.
     */
    @Test
    public void testConfig() {
        assertThat(dhcpL2Relay.useOltUplink, is(USE_OLT_ULPORT_FOR_PKT_INOUT));
        assertThat(dhcpL2Relay.modifyClientPktsSrcDstMac, is(MODIFY_SRC_DST_MAC));
        assertNull(dhcpL2Relay.dhcpServerConnectPoint.get());
    }

    /**
     * Tests if dhcpl2relay app has been configured.
     */
    @Test
    public void testDhcpL2RelayConfigured() {
        assertTrue(dhcpL2Relay.configured());
    }

    /**
     * Mocks the network config registry.
     */
    @SuppressWarnings({"unchecked", "TypeParameterUnusedInFormals"})
    static final class TestNetworkConfigRegistry
            extends NetworkConfigRegistryAdapter {
        @Override
        public <S, C extends Config<S>> C getConfig(S subject, Class<C> configClass) {
            DhcpL2RelayConfig dhcpConfig = new MockDhcpL2RelayConfig();
            return (C) dhcpConfig;
        }
    }
}