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

import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.TimeUnit;

import org.easymock.EasyMock;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.onlab.junit.TestUtils;
import org.onlab.packet.DHCP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.UDP;
import org.onlab.packet.dhcp.DhcpOption;

import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.flowobjective.FlowObjectiveServiceAdapter;
import org.opencord.dhcpl2relay.impl.packet.DhcpOption82;

import com.google.common.collect.Lists;

public class DhcpL2RelayTest extends DhcpL2RelayTestBase {

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
        dhcpL2Relay.hostService = new MockHostService();
        dhcpL2Relay.mastershipService = new MockMastershipService();
        dhcpL2Relay.dhcpL2RelayCounters = new MockDhcpL2RelayCountersStore();
        TestUtils.setField(dhcpL2Relay, "eventDispatcher", new TestEventDispatcher());
        dhcpL2Relay.refreshService = new MockExecutor(dhcpL2Relay.refreshService);
        dhcpL2Relay.activate(new DhcpL2RelayTestBase.MockComponentContext());
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
     * Tests the DHCP relay app by sending DHCP discovery Packet.
     *
     * @throws Exception when an unhandled error occurs
     */
    @Test
    public void testDhcpDiscover()  throws Exception {
        //  (1) Sending DHCP discover packet
        Ethernet discoverPacket = constructDhcpDiscoverPacket(CLIENT_MAC);

        sendPacket(discoverPacket, ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/" + 1));

        Ethernet discoverRelayed = (Ethernet) getPacket();
        compareClientPackets(discoverPacket, discoverRelayed);
    }

    /**
     * Tests the DHCP relay app by sending DHCP Request Packet.
     *
     * @throws Exception when an unhandled error occurs
     */
    @Test
    public void testDhcpRequest()  throws Exception {
        //  (1) Sending DHCP discover packet
        Ethernet requestPacket = constructDhcpRequestPacket(CLIENT_MAC);

        sendPacket(requestPacket, ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/" + 1));

        Ethernet requestRelayed = (Ethernet) getPacket();
        compareClientPackets(requestPacket, requestRelayed);
    }

    /**
     * Tests the DHCP relay app by sending DHCP Offer Packet.
     *
     * @throws Exception when an unhandled error occurs
     */
    @Test
    public void testDhcpOffer() {
        //  (1) Sending DHCP discover packet
        Ethernet offerPacket = constructDhcpOfferPacket(SERVER_MAC,
                CLIENT_MAC, DESTINATION_ADDRESS_IP, DHCP_CLIENT_IP_ADDRESS);

        sendPacket(offerPacket, ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/" + 1));

        Ethernet offerRelayed = (Ethernet) getPacket();
        compareServerPackets(offerPacket, offerRelayed);
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

        sendPacket(ackPacket, ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/" + 1));

        Ethernet ackRelayed = (Ethernet) getPacket();
        compareServerPackets(ackPacket, ackRelayed);
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

        Map<DhcpL2RelayCountersIdentifier, AtomicLong> countersMap = dhcpL2Relay.dhcpL2RelayCounters.getCountersMap();
        discoveryValue = countersMap.get(new DhcpL2RelayCountersIdentifier(DhcpL2RelayCountersIdentifier.GLOBAL_COUNTER,
                DhcpL2RelayCounters.valueOf("DHCPDISCOVER"))).longValue();
        offerValue = countersMap.get(new DhcpL2RelayCountersIdentifier(DhcpL2RelayCountersIdentifier.GLOBAL_COUNTER,
                DhcpL2RelayCounters.valueOf("DHCPOFFER"))).longValue();
        requestValue = countersMap.get(new DhcpL2RelayCountersIdentifier(DhcpL2RelayCountersIdentifier.GLOBAL_COUNTER,
                DhcpL2RelayCounters.valueOf("DHCPREQUEST"))).longValue();
        ackValue = countersMap.get(new DhcpL2RelayCountersIdentifier(DhcpL2RelayCountersIdentifier.GLOBAL_COUNTER,
                DhcpL2RelayCounters.valueOf("DHCPACK"))).longValue();

        assertEquals((long) 1, discoveryValue);
        assertEquals((long) 1, offerValue);
        assertEquals((long) 1, requestValue);
        assertEquals((long) 1, ackValue);
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

        Map<DhcpL2RelayCountersIdentifier, AtomicLong> countersMap = dhcpL2Relay.dhcpL2RelayCounters.getCountersMap();
        discoveryValue = countersMap.get(new DhcpL2RelayCountersIdentifier(CLIENT_ID_1,
                DhcpL2RelayCounters.valueOf("DHCPDISCOVER"))).longValue();
        offerValue = countersMap.get(new DhcpL2RelayCountersIdentifier(CLIENT_ID_1,
                DhcpL2RelayCounters.valueOf("DHCPOFFER"))).longValue();
        requestValue = countersMap.get(new DhcpL2RelayCountersIdentifier(CLIENT_ID_1,
                DhcpL2RelayCounters.valueOf("DHCPREQUEST"))).longValue();
        ackValue = countersMap.get(new DhcpL2RelayCountersIdentifier(CLIENT_ID_1,
                DhcpL2RelayCounters.valueOf("DHCPACK"))).longValue();

        assertEquals((long) 1, discoveryValue);
        assertEquals((long) 1, offerValue);
        assertEquals((long) 1, requestValue);
        assertEquals((long) 1, ackValue);
    }

    /**
     * Tests the schedule function to publish the counters to kafka.
     *
     */
    @Test
    public void testSchedulePublishCountersToKafka() {
        MockExecutor executor = new MockExecutor(dhcpL2Relay.refreshService);
        dhcpL2Relay.refreshTask = executor.scheduleWithFixedDelay(
                dhcpL2Relay.publishCountersToKafka, 0, 10, TimeUnit.SECONDS);
        executor.assertLastMethodCalled("scheduleWithFixedDelay", 0, 10, TimeUnit.SECONDS);
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
        public void initCounters(String counterClass) {

        }

        @Override
        public void incrementCounter(String counterClass, DhcpL2RelayCounters counterType) {

        }

        @Override
        public void setCounter(String counterClass, DhcpL2RelayCounters counterType, Long value) {

        }

        @Override
        public Map<DhcpL2RelayCountersIdentifier, AtomicLong> getCountersMap() {
            return new HashMap<>();
        }

        @Override
        public void resetCounters(String counterClass) {

        }
    }
}