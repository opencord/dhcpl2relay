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

import static org.easymock.EasyMock.createMock;
import static org.junit.Assert.assertEquals;
import static org.slf4j.LoggerFactory.getLogger;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.onlab.junit.TestUtils;
import org.onlab.packet.DHCP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.MacAddress;
import org.onlab.packet.UDP;
import org.onlab.packet.VlanId;
import org.onlab.packet.dhcp.DhcpOption;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.cluster.ClusterServiceAdapter;
import org.onosproject.cluster.LeadershipServiceAdapter;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.flowobjective.FlowObjectiveServiceAdapter;
import org.onosproject.store.cluster.messaging.ClusterCommunicationServiceAdapter;
import org.onosproject.store.service.TestStorageService;
import org.opencord.dhcpl2relay.DhcpAllocationInfo;
import org.opencord.dhcpl2relay.DhcpL2RelayEvent;
import org.opencord.dhcpl2relay.DhcpL2RelayStoreDelegate;
import org.opencord.dhcpl2relay.impl.packet.DhcpOption82;
import org.slf4j.Logger;

import com.google.common.collect.Lists;

public class DhcpL2RelayTest extends DhcpL2RelayTestBase {

    private DhcpL2Relay dhcpL2Relay;
    private SimpleDhcpL2RelayCountersStore store;
    private final Logger log = getLogger(getClass());
    Map<String, DhcpAllocationInfo> allocs;

    ComponentConfigService mockConfigService =
            createMock(ComponentConfigService.class);

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
        dhcpL2Relay.hostService = new MockHostService();
        dhcpL2Relay.mastershipService = new MockMastershipService();
        dhcpL2Relay.dhcpL2RelayCounters = new MockDhcpL2RelayCountersStore();
        dhcpL2Relay.storageService = new TestStorageService();
        dhcpL2Relay.leadershipService = new LeadershipServiceAdapter();
        TestUtils.setField(dhcpL2Relay, "eventDispatcher", new TestEventDispatcher());
        dhcpL2Relay.refreshService = new MockExecutor(dhcpL2Relay.refreshService);
        dhcpL2Relay.activate(new DhcpL2RelayTestBase.MockComponentContext());
        store = new SimpleDhcpL2RelayCountersStore();
        store.storageService = new TestStorageService();
        store.leadershipService = new LeadershipServiceAdapter();
        store.clusterService = new ClusterServiceAdapter();
        store.clusterCommunicationService = new ClusterCommunicationServiceAdapter();
        store.componentConfigService = mockConfigService;
        TestUtils.setField(store, "eventDispatcher", new TestEventDispatcher());
        store.activate(new MockComponentContext());
        dhcpL2Relay.dhcpL2RelayCounters = this.store;
    }

    /**
     * Tears down the dhcpL2Relay application.
     */
    @After
    public void tearDown() {
        dhcpL2Relay.deactivate();
    }

    private void checkAllocation(DHCP.MsgType messageType) {
        ConnectPoint clientCp = ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/"
                + String.valueOf(CLIENT_PORT));
        allocs = dhcpL2Relay.getAllocationInfo();
        assert allocs.size() == 1;
        allocs.forEach((k, v) -> {
            log.info("Allocation {} : {}", k, v);
            assertEquals(v.type(), messageType);
            assertEquals(v.macAddress(), CLIENT_MAC);
            assertEquals(v.location(), clientCp);
        });
    }

    @Test
    public void testMultipleAllocations() throws Exception {
        dhcpL2Relay.clearAllocations();
        // Trigger a discover from one RG on port 32
        MacAddress mac32 = MacAddress.valueOf("b4:96:91:0c:4f:e4");
        VlanId vlan32a = VlanId.vlanId((short) 801);
        Ethernet discover32a = constructDhcpDiscoverPacket(
                                  mac32, vlan32a, (short) 0);
        ConnectPoint client32 = ConnectPoint.deviceConnectPoint(
                                                "of:0000b86a974385f7/32");
        sendPacket(discover32a, client32);
        allocs = dhcpL2Relay.getAllocationInfo();
        assert allocs.size() == 1;

        //Trigger a discover from another RG on port 4112
        MacAddress mac4112 = MacAddress.valueOf("b4:96:91:0c:4f:c9");
        VlanId vlan4112 = VlanId.vlanId((short) 101);
        Ethernet discover4112 = constructDhcpDiscoverPacket(
                                                            mac4112, vlan4112,
                                                            (short) 0);
        ConnectPoint client4112 = ConnectPoint.deviceConnectPoint(
                "of:0000b86a974385f7/4112");
        sendPacket(discover4112, client4112);
        allocs = dhcpL2Relay.getAllocationInfo();
        assert allocs.size() == 2;

        // Trigger a discover for another service with a different vlan
        // from the same UNI port 32
        VlanId vlan32b = VlanId.vlanId((short) 802);
        Ethernet discover32b = constructDhcpDiscoverPacket(
                                  mac32, vlan32b, (short) 0);
        sendPacket(discover32b, client32);
        allocs = dhcpL2Relay.getAllocationInfo();
        assert allocs.size() == 3;

        allocs.forEach((k, v) -> {
            log.info("Allocation {} : {}", k, v);
            assertEquals(v.type(), DHCP.MsgType.DHCPDISCOVER);
            if (v.subscriberId().equals("ALPHe3d1cea3-1")) {
                assertEquals(v.macAddress(), mac32);
                assertEquals(v.location(), client32);
                if (!(v.vlanId().equals(vlan32a) || v.vlanId().equals(vlan32b))) {
                    assert false;
                }
            } else if (v.subscriberId().equals("ALPHe3d1ceb7-1")) {
                assertEquals(v.macAddress(), mac4112);
                assertEquals(v.location(), client4112);
                assertEquals(v.vlanId(), vlan4112);
            } else {
                assert false;
            }
        });

        dhcpL2Relay.clearAllocations();
        assert dhcpL2Relay.getAllocationInfo().size() == 0;
    }

    /**
     * Tests the DHCP relay app by sending DHCP discovery Packet.
     *
     * @throws Exception when an unhandled error occurs
     */
    @Test
    public void testDhcpDiscover()  throws Exception {
        // Sending DHCP Discover packet
        dhcpL2Relay.clearAllocations();
        Ethernet discoverPacket = constructDhcpDiscoverPacket(CLIENT_MAC);
        ConnectPoint clientCp = ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/"
                + String.valueOf(CLIENT_PORT));
        sendPacket(discoverPacket, clientCp);

        Ethernet discoverRelayed = (Ethernet) getPacket();
        compareClientPackets(discoverPacket, discoverRelayed);
        checkAllocation(DHCP.MsgType.DHCPDISCOVER);
    }

    /**
     * Tests the DHCP relay app by sending DHCP Request Packet.
     *
     * @throws Exception when an unhandled error occurs
     */
    @Test
    public void testDhcpRequest()  throws Exception {
        // Sending DHCP Request packet
        Ethernet requestPacket = constructDhcpRequestPacket(CLIENT_MAC);
        ConnectPoint clientCp = ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/"
                + String.valueOf(CLIENT_PORT));
        sendPacket(requestPacket, clientCp);

        Ethernet requestRelayed = (Ethernet) getPacket();
        compareClientPackets(requestPacket, requestRelayed);
        checkAllocation(DHCP.MsgType.DHCPREQUEST);
    }

    /**
     * Tests the DHCP relay app by sending DHCP Offer Packet.
     *
     * @throws Exception when an unhandled error occurs
     */
    @Test
    public void testDhcpOffer() {
        // Sending DHCP Offer packet
        Ethernet offerPacket = constructDhcpOfferPacket(SERVER_MAC,
                CLIENT_MAC, DESTINATION_ADDRESS_IP, DHCP_CLIENT_IP_ADDRESS);
        sendPacket(offerPacket, ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/"
                + String.valueOf(UPLINK_PORT)));

        Ethernet offerRelayed = (Ethernet) getPacket();
        compareServerPackets(offerPacket, offerRelayed);
        checkAllocation(DHCP.MsgType.DHCPOFFER);
    }

    /**
     * Tests the DHCP relay app by sending DHCP Ack Packet.
     *
     * @throws Exception when an unhandled error occurs
     */
    @Test
    public void testDhcpAck() {

        Ethernet ackPacket = constructDhcpAckPacket(SERVER_MAC,
                CLIENT_MAC, DESTINATION_ADDRESS_IP, DHCP_CLIENT_IP_ADDRESS);

        sendPacket(ackPacket, ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/"
                + String.valueOf(UPLINK_PORT)));

        Ethernet ackRelayed = (Ethernet) getPacket();
        compareServerPackets(ackPacket, ackRelayed);
        checkAllocation(DHCP.MsgType.DHCPACK);
    }

    /**
     * Tests the DHCP relay app by sending DHCP Nak Packet.
     *
     * @throws Exception when an unhandled error occurs
     */
    @Test
    public void testDhcpNak() {

        Ethernet nakPacket = constructDhcpNakPacket(SERVER_MAC,
                CLIENT_MAC, DESTINATION_ADDRESS_IP, DHCP_CLIENT_IP_ADDRESS);

        sendPacket(nakPacket, ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/" + 1));

        Ethernet nakRelayed = (Ethernet) getPacket();
        compareServerPackets(nakPacket, nakRelayed);
        checkAllocation(DHCP.MsgType.DHCPNAK);
    }

    /**
     * Tests the DHCP relay app by sending DHCP Decline Packet.
     *
     * @throws Exception when an unhandled error occurs
     */
    @Test
    public void testDhcpDecline() {

        Ethernet declinePacket = constructDhcpDeclinePacket(CLIENT_MAC);

        sendPacket(declinePacket, ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/" + 1));

        Ethernet declineRelayed = (Ethernet) getPacket();
        compareClientPackets(declinePacket, declineRelayed);
        checkAllocation(DHCP.MsgType.DHCPDECLINE);
    }

    /**
     * Tests the DHCP global counters.
     */
    @Test
    public void testDhcpGlobalCounters() {
        long discoveryValue = 0;
        long offerValue = 0;
        long requestValue = 0;
        long ackValue = 0;

        Ethernet discoverPacket = constructDhcpDiscoverPacket(CLIENT_MAC);
        Ethernet offerPacket = constructDhcpOfferPacket(SERVER_MAC,
                CLIENT_MAC, DESTINATION_ADDRESS_IP, DHCP_CLIENT_IP_ADDRESS);
        Ethernet requestPacket = constructDhcpRequestPacket(CLIENT_MAC);
        Ethernet ackPacket = constructDhcpAckPacket(SERVER_MAC,
                CLIENT_MAC, DESTINATION_ADDRESS_IP, DHCP_CLIENT_IP_ADDRESS);

        sendPacket(discoverPacket, ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/" + 1));
        sendPacket(offerPacket, ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/" + 1));
        sendPacket(requestPacket, ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/" + 1));
        sendPacket(ackPacket, ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/" + 1));

        Map<DhcpL2RelayCountersIdentifier, Long> countersMap = store.getCountersMap();
        discoveryValue = countersMap.get(new DhcpL2RelayCountersIdentifier(DhcpL2RelayEvent.GLOBAL_COUNTER,
                DhcpL2RelayCounterNames.valueOf("DHCPDISCOVER")));
        offerValue = countersMap.get(new DhcpL2RelayCountersIdentifier(DhcpL2RelayEvent.GLOBAL_COUNTER,
                DhcpL2RelayCounterNames.valueOf("DHCPOFFER")));
        requestValue = countersMap.get(new DhcpL2RelayCountersIdentifier(DhcpL2RelayEvent.GLOBAL_COUNTER,
                DhcpL2RelayCounterNames.valueOf("DHCPREQUEST")));
        ackValue = countersMap.get(new DhcpL2RelayCountersIdentifier(DhcpL2RelayEvent.GLOBAL_COUNTER,
                DhcpL2RelayCounterNames.valueOf("DHCPACK")));

        assertEquals(1, discoveryValue);
        assertEquals(1, offerValue);
        assertEquals(1, requestValue);
        assertEquals(1, ackValue);
    }

    /**
     * Tests the DHCP per subscriber counters.
     *
     */
    @Test
    public void testDhcpPerSubscriberCounters() {
        long discoveryValue;
        long offerValue;
        long requestValue;
        long ackValue;

        Ethernet discoverPacket = constructDhcpDiscoverPacket(CLIENT_MAC);
        Ethernet offerPacket = constructDhcpOfferPacket(SERVER_MAC,
                CLIENT_MAC, DESTINATION_ADDRESS_IP, DHCP_CLIENT_IP_ADDRESS);
        Ethernet requestPacket = constructDhcpRequestPacket(CLIENT_MAC);
        Ethernet ackPacket = constructDhcpAckPacket(SERVER_MAC,
                CLIENT_MAC, DESTINATION_ADDRESS_IP, DHCP_CLIENT_IP_ADDRESS);

        sendPacket(discoverPacket, ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/" + 1));
        sendPacket(offerPacket, ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/" + 1));
        sendPacket(requestPacket, ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/" + 1));
        sendPacket(ackPacket, ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/" + 1));

        Map<DhcpL2RelayCountersIdentifier, Long> countersMap = store.getCountersMap();
        discoveryValue = countersMap.get(new DhcpL2RelayCountersIdentifier(CLIENT_ID_1,
                DhcpL2RelayCounterNames.valueOf("DHCPDISCOVER")));
        offerValue = countersMap.get(new DhcpL2RelayCountersIdentifier(CLIENT_ID_1,
                DhcpL2RelayCounterNames.valueOf("DHCPOFFER")));
        requestValue = countersMap.get(new DhcpL2RelayCountersIdentifier(CLIENT_ID_1,
                DhcpL2RelayCounterNames.valueOf("DHCPREQUEST")));
        ackValue = countersMap.get(new DhcpL2RelayCountersIdentifier(CLIENT_ID_1,
                DhcpL2RelayCounterNames.valueOf("DHCPACK")));

        assertEquals(1, discoveryValue);
        assertEquals(1, offerValue);
        assertEquals(1, requestValue);
        assertEquals(1, ackValue);
    }

    public void compareClientPackets(Ethernet sent, Ethernet relayed) {
        sent.setSourceMACAddress(OLT_MAC_ADDRESS);
        sent.setQinQVID(CLIENT_S_TAG.toShort());
        sent.setVlanID(CLIENT_C_TAG.toShort());
        sent.setPriorityCode((byte) CLIENT_C_PBIT);

        IPv4 ipv4Packet = (IPv4) sent.getPayload();
        UDP udpPacket = (UDP) ipv4Packet.getPayload();
        DHCP dhcpPacket = (DHCP) udpPacket.getPayload();

        List<DhcpOption> options = Lists.newArrayList(dhcpPacket.getOptions());
        DhcpOption82 option82 = new DhcpOption82();
        option82.setAgentCircuitId(CLIENT_CIRCUIT_ID);

        DhcpOption option = new DhcpOption()
                .setCode(DHCP.DHCPOptionCode.OptionCode_CircuitID.getValue())
                .setData(option82.toByteArray())
                .setLength(option82.length());

        options.add(options.size() - 1, option);
        dhcpPacket.setOptions(options);
        assertEquals(sent, relayed);

    }

    public void compareServerPackets(Ethernet sent, Ethernet relayed) {
        sent.setDestinationMACAddress(CLIENT_MAC);
        sent.setQinQVID(NOT_PROVIDED);
        sent.setQinQPriorityCode((byte) NOT_PROVIDED);
        sent.setVlanID(CLIENT_C_TAG.toShort());

        final ByteBuffer byteBuffer = ByteBuffer.wrap(sent.serialize());
        Ethernet expectedPacket = null;
        try {
            expectedPacket = Ethernet.deserializer().deserialize(byteBuffer.array(),
                    0, byteBuffer.array().length);
        } catch (Exception e) {
        }
        assertEquals(expectedPacket, relayed);

    }

    private class MockDhcpL2RelayCountersStore implements DhcpL2RelayCountersStore {

        @Override
        public void incrementCounter(String counterClass, DhcpL2RelayCounterNames counterType) {

        }

        @Override
        public void setCounter(String counterClass, DhcpL2RelayCounterNames counterType, Long value) {

        }

        @Override
        public DhcpL2RelayStatistics getCounters() {
            return new DhcpL2RelayStatistics();
        }

        @Override
        public void resetCounters(String counterClass) {

        }

        @Override
        public void setDelegate(DhcpL2RelayStoreDelegate delegate) {
        }

        @Override
        public void unsetDelegate(DhcpL2RelayStoreDelegate delegate) {
        }

        @Override
        public boolean hasDelegate() {
            return false;
        }
    }
}