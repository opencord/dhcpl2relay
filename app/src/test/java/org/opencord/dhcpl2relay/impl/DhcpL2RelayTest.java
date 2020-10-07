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
import static org.junit.Assert.fail;
import static org.slf4j.LoggerFactory.getLogger;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.onlab.junit.TestUtils;
import org.onlab.packet.DHCP;
import org.onlab.packet.DeserializationException;
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
import org.opencord.dhcpl2relay.impl.packet.DhcpOption82Data;
import org.slf4j.Logger;

import com.google.common.collect.Lists;
import com.google.common.util.concurrent.MoreExecutors;

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
        TestUtils.setField(dhcpL2Relay, "packetProcessorExecutor", MoreExecutors.newDirectExecutorService());
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

    private void checkAllocation(DHCP.MsgType messageType, String circuitId) {
        ConnectPoint clientCp = ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/"
                                                + String.valueOf(CLIENT_PORT));
        allocs = dhcpL2Relay.getAllocationInfo();
        assertEquals(1, allocs.size());
        allocs.forEach((k, v) -> {
            log.info("Allocation {} : {}", k, v);
            assertEquals(v.type(), messageType);
            assertEquals(v.macAddress(), CLIENT_MAC);
            assertEquals(v.location(), clientCp);
            assertEquals(v.circuitId(), circuitId);
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
        assertEquals(1, allocs.size());

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
        assertEquals(2, allocs.size());

        // Trigger a discover for another service with a different vlan
        // from the same UNI port 32
        VlanId vlan32b = VlanId.vlanId((short) 802);
        Ethernet discover32b = constructDhcpDiscoverPacket(
                mac32, vlan32b, (short) 0);
        sendPacket(discover32b, client32);

        allocs = dhcpL2Relay.getAllocationInfo();
        assertEquals(3, allocs.size());

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
     * Tests the DHCP relay app by sending DHCP discovery Packet. The circuitId
     * and remote-Id for this client is operator defined in MockSadis.
     *
     * @throws Exception when an unhandled error occurs
     */
    @Test
    public void testDhcpDiscover() throws Exception {
        // Sending DHCP Discover packet
        dhcpL2Relay.clearAllocations();
        Ethernet discoverPacket = constructDhcpDiscoverPacket(CLIENT_MAC);
        ConnectPoint clientCp = ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/"
                                    + String.valueOf(CLIENT_PORT));
        // send a copy of the packet as the app code modifies the sent packet
        sendPacket(discoverPacket.duplicate(), clientCp);

        Ethernet discoverRelayed = (Ethernet) getPacket();
        compareClientPackets(discoverPacket, discoverRelayed);
        checkAllocation(DHCP.MsgType.DHCPDISCOVER, CLIENT_CIRCUIT_ID);
    }

    /**
     * Tests the addition of app-defined circuit id, when this client's
     * MockSadis config for circiutId is empty. The remoteId is configured.
     *
     * @throws Exception when an unhandled error occurs
     */
    @Test
    public void testDhcpDiscoverEmptyCircuitId() throws Exception {
        dhcpL2Relay.clearAllocations();
        MacAddress mac32 = MacAddress.valueOf("b4:96:91:0c:4f:e4");
        VlanId vlan32a = VlanId.vlanId((short) 801); // defined in mockSadis
        VlanId qinq32a = VlanId.vlanId((short) 111);
        Ethernet discover32a = constructDhcpDiscoverPacket(mac32, vlan32a,
                                                           (short) 0);
        ConnectPoint client32 = ConnectPoint
                .deviceConnectPoint("of:0000b86a974385f7/32");
        sendPacket(discover32a.duplicate(), client32);
        Ethernet discoverRelayed = (Ethernet) getPacket();
        // empty circuitId in sadis for client32 should result in app defined
        // circuitId
        String expectedCircuitId = client32 + ":vlan" + vlan32a + ":pcp-1";
        compareClientPackets(discover32a, discoverRelayed,
                             qinq32a, vlan32a, CLIENT_C_PBIT,
                             expectedCircuitId,
                             CLIENT_REMOTE_ID);
        allocs = dhcpL2Relay.getAllocationInfo();
        allocs.forEach((k, v) -> {
            log.info("Allocation {} : {}", k, v);
            assertEquals(v.circuitId(), expectedCircuitId);
        });
    }

    /**
     * Tests the addition of app-defined circuit id, when this client's
     * MockSadis config for circuitId and remoteId are null. In addition, it
     * tests that the configured downstream-pcp is included in the circuitId.
     *
     * @throws Exception when an unhandled error occurs
     */
    @Test
    public void testDhcpDiscoverNullIds() throws Exception {
        dhcpL2Relay.clearAllocations();
        MacAddress mac4112 = MacAddress.valueOf("b4:96:91:0c:4f:c9");
        VlanId vlan4112 = VlanId.vlanId((short) 101);
        VlanId qinq4112 = VlanId.vlanId((short) 222);
        Ethernet discover4112 = constructDhcpDiscoverPacket(mac4112, vlan4112,
                                                            (short) 0);
        ConnectPoint client4112 = ConnectPoint
                .deviceConnectPoint("of:0000b86a974385f7/4112");
        sendPacket(discover4112.duplicate(), client4112);
        Ethernet discoverRelayed = (Ethernet) getPacket();
        // null circuitId in sadis for client32 should result in app defined
        // circuitId. remoteId should not be there. Correct downstream pbit
        // should be used
        String expectedCircuitId = client4112 + ":vlan" + vlan4112 + ":pcp5";
        compareClientPackets(discover4112, discoverRelayed,
                             qinq4112, vlan4112, CLIENT_C_PBIT,
                             expectedCircuitId,
                             null);
        allocs = dhcpL2Relay.getAllocationInfo();
        allocs.forEach((k, v) -> {
            log.info("Allocation {} : {}", k, v);
            assertEquals(v.circuitId(), expectedCircuitId);
        });
    }

    /**
     * Tests the DHCP relay app by sending DHCP Request Packet.
     *
     * @throws Exception when an unhandled error occurs
     */
    @Test
    public void testDhcpRequest() throws Exception {
        // Sending DHCP Request packet
        Ethernet requestPacket = constructDhcpRequestPacket(CLIENT_MAC);
        ConnectPoint clientCp = ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/"
                                                + String.valueOf(CLIENT_PORT));
        sendPacket(requestPacket.duplicate(), clientCp);

        Ethernet requestRelayed = (Ethernet) getPacket();
        compareClientPackets(requestPacket, requestRelayed);
        checkAllocation(DHCP.MsgType.DHCPREQUEST, CLIENT_CIRCUIT_ID);
    }

    /**
     * Tests the DHCP relay app by sending DHCP Offer Packet with app-defined
     * circuit id. App should use the circuit id for forwarding.
     *
     * @throws Exception when an unhandled error occurs
     */
    @Test
    public void testDhcpOffer() throws InterruptedException {
        // Sending DHCP Offer packet
        Ethernet offerPacket = constructDhcpOfferPacket(SERVER_MAC, CLIENT_MAC,
                                                        DESTINATION_ADDRESS_IP,
                                                        DHCP_CLIENT_IP_ADDRESS);
        sendPacket(offerPacket, ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/"
                                         + String.valueOf(UPLINK_PORT)));

        Ethernet offerRelayed = (Ethernet) getPacket();
        compareServerPackets(offerPacket, offerRelayed);
        String expectedCircuitId = OLT_DEV_ID + "/" + CLIENT_PORT + ":vlan"
                + CLIENT_C_TAG + ":pcp" + CLIENT_C_PBIT;
        checkAllocation(DHCP.MsgType.DHCPOFFER, expectedCircuitId);
    }

    /**
     * Tests the DHCP relay app by sending DHCP Ack Packet with operator defined
     * circuit id. App should ignore circuit Id and do a host lookup.
     *
     * @throws Exception when an unhandled error occurs
     */
    @Test
    public void testDhcpAck() throws InterruptedException {

        Ethernet ackPacket = constructDhcpAckPacket(SERVER_MAC, CLIENT_MAC,
                                                    DESTINATION_ADDRESS_IP,
                                                    DHCP_CLIENT_IP_ADDRESS);

        sendPacket(ackPacket, ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/"
                                                + String.valueOf(UPLINK_PORT)));

        Ethernet ackRelayed = (Ethernet) getPacket();
        compareServerPackets(ackPacket, ackRelayed);
        checkAllocation(DHCP.MsgType.DHCPACK, CLIENT_CIRCUIT_ID);
    }

    /**
     * Tests the DHCP relay app by sending DHCP Nak Packet.
     * Tests app-defined option82, but uses incorrect connectPoint - packet
     * should still be forwarded to this connectPoint (ie without host lookup).
     * Also pbit in circuitId is -1, which means original pbit should be retained
     *
     * @throws Exception when an unhandled error occurs
     */
    @Test
    public void testDhcpNak() throws InterruptedException {
        VlanId fakeVlan = VlanId.vlanId((short) 50);
        short fakePcp = (short) 4; // should be retained
        VlanId expectedVlan = VlanId.vlanId((short) 111);
        // relayed packet should have vlan 111 and retain pcp4 and be sent out
        // of port32
        ConnectPoint fakeCp = ConnectPoint.fromString("of:0000b86a974385f7/32");
        String fakeCircuitId = fakeCp + ":vlan"
                + expectedVlan + ":pcp-1";
        Ethernet nakPacket = constructDhcpNakPacket(SERVER_MAC, CLIENT_MAC,
                                                    DESTINATION_ADDRESS_IP,
                                                    DHCP_CLIENT_IP_ADDRESS,
                                                    fakeVlan,
                                                    fakePcp);

        sendPacket(nakPacket, ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/"
                                                + String.valueOf(UPLINK_PORT)));

        Ethernet nakRelayed = (Ethernet) getPacket();
        compareServerPackets(nakPacket, nakRelayed, expectedVlan, fakePcp);

        allocs = dhcpL2Relay.getAllocationInfo();
        assertEquals(1, allocs.size());
        allocs.forEach((k, v) -> {
            log.info("Allocation {} : {}", k, v);
            assertEquals(v.type(), DHCP.MsgType.DHCPNAK);
            assertEquals(v.macAddress(), CLIENT_MAC);
            assertEquals(v.location(), fakeCp);
            assertEquals(v.circuitId(), fakeCircuitId);
        });
    }

    /**
     * Tests the DHCP relay app by sending DHCP Decline Packet.
     *
     * @throws Exception when an unhandled error occurs
     */
    @Test
    public void testDhcpDecline() throws InterruptedException {

        Ethernet declinePacket = constructDhcpDeclinePacket(CLIENT_MAC);

        sendPacket(declinePacket.duplicate(),
                   ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/" + 1));

        Ethernet declineRelayed = (Ethernet) getPacket();
        compareClientPackets(declinePacket, declineRelayed);
        checkAllocation(DHCP.MsgType.DHCPDECLINE, CLIENT_CIRCUIT_ID);
    }

    /**
     * Tests the DHCP global counters.
     */
    @Test
    public void testDhcpGlobalCounters() throws InterruptedException {

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
        long discoveryValue = countersMap.get(new DhcpL2RelayCountersIdentifier(DhcpL2RelayEvent.GLOBAL_COUNTER,
                                                  DhcpL2RelayCounterNames.valueOf("DHCPDISCOVER")));
        long offerValue = countersMap.get(new DhcpL2RelayCountersIdentifier(DhcpL2RelayEvent.GLOBAL_COUNTER,
                                              DhcpL2RelayCounterNames.valueOf("DHCPOFFER")));
        long requestValue = countersMap.get(new DhcpL2RelayCountersIdentifier(DhcpL2RelayEvent.GLOBAL_COUNTER,
                                                DhcpL2RelayCounterNames.valueOf("DHCPREQUEST")));
        long ackValue = countersMap.get(new DhcpL2RelayCountersIdentifier(DhcpL2RelayEvent.GLOBAL_COUNTER,
                                            DhcpL2RelayCounterNames.valueOf("DHCPACK")));
        assertEquals(1, discoveryValue);
        assertEquals(1, offerValue);
        assertEquals(1, requestValue);
        assertEquals(1, ackValue);
    }

    /**
     * Tests the DHCP per subscriber counters.
     */
    @Test
    public void testDhcpPerSubscriberCounters() throws Exception {

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
        long discoveryValue = countersMap.get(new DhcpL2RelayCountersIdentifier(CLIENT_ID_1,
                                                  DhcpL2RelayCounterNames.valueOf("DHCPDISCOVER")));
        long offerValue = countersMap.get(new DhcpL2RelayCountersIdentifier(CLIENT_ID_1,
                                              DhcpL2RelayCounterNames.valueOf("DHCPOFFER")));
        long requestValue = countersMap.get(new DhcpL2RelayCountersIdentifier(CLIENT_ID_1,
                                                DhcpL2RelayCounterNames.valueOf("DHCPREQUEST")));
        long ackValue = countersMap.get(new DhcpL2RelayCountersIdentifier(CLIENT_ID_1,
                                            DhcpL2RelayCounterNames.valueOf("DHCPACK")));
        assertEquals(1, discoveryValue);
        assertEquals(1, offerValue);
        assertEquals(1, requestValue);
        assertEquals(1, ackValue);
    }

    public void compareClientPackets(Ethernet sent, Ethernet relayed) {
        compareClientPackets(sent, relayed, CLIENT_S_TAG, CLIENT_C_TAG,
                             CLIENT_C_PBIT, CLIENT_CIRCUIT_ID,
                             CLIENT_REMOTE_ID);
    }

    public void compareClientPackets(Ethernet sent, Ethernet relayed,
                                     VlanId expectedQinQ,
                                     VlanId expectedVlan, short expectedPcp,
                                     String expectedCircuitId,
                                     String expectedRemoteId) {
        // convert the sent packet to the expected relayed packet
        sent.setSourceMACAddress(OLT_MAC_ADDRESS); // due to netconfig test in setup
        sent.setQinQVID(expectedQinQ.toShort());
        sent.setQinQTPID((short) 0x8100);
        sent.setVlanID(expectedVlan.toShort());
        sent.setPriorityCode((byte) expectedPcp);

        IPv4 ipv4Packet = (IPv4) sent.getPayload();
        UDP udpPacket = (UDP) ipv4Packet.getPayload();
        DHCP dhcpPacket = (DHCP) udpPacket.getPayload();
        List<DhcpOption> options = Lists.newArrayList(dhcpPacket.getOptions());

        DhcpOption82Data option82 = new DhcpOption82Data();
        option82.setAgentCircuitId(expectedCircuitId);
        option82.setAgentRemoteId(expectedRemoteId);

        DhcpOption option = new DhcpOption()
                .setCode(DHCP.DHCPOptionCode.OptionCode_CircuitID.getValue())
                .setData(option82.toByteArray())
                .setLength(option82.length());

        options.add(options.size() - 1, option);
        dhcpPacket.setOptions(options);

        byte[] sb = sent.serialize();
        Ethernet expectedPacket = null;
        try {
            expectedPacket = Ethernet.deserializer()
                    .deserialize(sb, 0, sb.length);
        } catch (DeserializationException e) {
            log.error("exeption: {}", e.getMessage());
            fail();
        }
        verifyDhcpOptions(expectedPacket, relayed);
        assertEquals(expectedPacket, relayed);
    }

    public void verifyDhcpOptions(Ethernet expected, Ethernet relayed) {
        DHCP de = ((DHCP) ((UDP) ((IPv4) expected.getPayload()).getPayload())
                .getPayload());
        DHCP dr = ((DHCP) ((UDP) ((IPv4) relayed.getPayload()).getPayload())
                .getPayload());
        List<DhcpOption> del = de.getOptions();
        List<DhcpOption> der = dr.getOptions();
        assertEquals(del.size(), der.size());
        for (int i = 0; i < del.size(); i++) {
            assertEquals(del.get(i), der.get(i));
        }
    }

    public void compareServerPackets(Ethernet sent, Ethernet relayed) {
        compareServerPackets(sent, relayed, CLIENT_C_TAG, CLIENT_C_PBIT);
    }

    public void compareServerPackets(Ethernet sent, Ethernet relayed,
                                     VlanId expectedVlan, short expectedPcp) {
        try {
            // modify sent packet to create expected packet
            sent.setDestinationMACAddress(CLIENT_MAC);
            sent.setQinQVID(NOT_PROVIDED);
            sent.setQinQPriorityCode((byte) NOT_PROVIDED);
            sent.setVlanID(expectedVlan.toShort());
            sent.setPriorityCode((byte) expectedPcp);
            DHCP d = ((DHCP) ((UDP) ((IPv4) sent.getPayload()).getPayload())
                    .getPayload());
            List<DhcpOption> newOptions = d.getOptions().stream()
                    .filter(option -> option
                            .getCode() != DHCP.DHCPOptionCode.OptionCode_CircuitID
                                    .getValue())
                    .collect(Collectors.toList());
            d.setOptions(newOptions);

            final ByteBuffer byteBuffer = ByteBuffer.wrap(sent.serialize());
            Ethernet expectedPacket = Ethernet.deserializer().deserialize(byteBuffer.array(),
                                                                          0, byteBuffer.array().length);
            assertEquals(expectedPacket, relayed);
        } catch (Exception e) {
            log.error(e.getMessage());
            fail();
        }

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