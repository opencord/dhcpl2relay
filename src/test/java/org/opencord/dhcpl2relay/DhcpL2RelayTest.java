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
package org.opencord.dhcpl2relay;

import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Set;

import org.easymock.EasyMock;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.onlab.junit.TestUtils;
import org.onlab.osgi.ComponentContextAdapter;
import org.onlab.packet.ChassisId;
import org.onlab.packet.DHCP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.UDP;
import org.onlab.packet.VlanId;
import org.onlab.packet.dhcp.DhcpOption;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.common.event.impl.TestEventDispatcher;
import org.onosproject.mastership.MastershipServiceAdapter;
import org.onosproject.net.AnnotationKeys;
import org.onosproject.net.Annotations;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DefaultAnnotations;
import org.onosproject.net.DefaultDevice;
import org.onosproject.net.DefaultHost;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Element;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.HostLocation;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.config.Config;
import org.onosproject.net.config.NetworkConfigRegistryAdapter;
import org.onosproject.net.device.DeviceServiceAdapter;
import org.onosproject.net.flowobjective.FlowObjectiveServiceAdapter;
import org.onosproject.net.host.HostServiceAdapter;
import org.onosproject.net.provider.ProviderId;
import org.opencord.dhcpl2relay.packet.DhcpOption82;
import org.opencord.sadis.SubscriberAndDeviceInformation;
import org.opencord.sadis.SubscriberAndDeviceInformationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;

public class DhcpL2RelayTest extends DhcpL2RelayTestBase {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private DhcpL2Relay dhcpL2Relay;

    private static final MacAddress CLIENT_MAC = MacAddress.valueOf("00:00:00:00:00:01");
    private static final VlanId CLIENT_C_TAG = VlanId.vlanId((short) 999);
    private static final VlanId CLIENT_S_TAG = VlanId.vlanId((short) 111);
    private static final String CLIENT_NAS_PORT_ID = "PON 1/1";
    private static final String CLIENT_CIRCUIT_ID = "CIR-PON 1/1";

    private static final String OLT_DEV_ID = "of:00000000000000aa";
    private static final MacAddress OLT_MAC_ADDRESS = MacAddress.valueOf("01:02:03:04:05:06");
    private static final DeviceId DEVICE_ID_1 = DeviceId.deviceId(OLT_DEV_ID);

    private static final ConnectPoint SERVER_CONNECT_POINT =
            ConnectPoint.deviceConnectPoint("of:0000000000000001/5");

    private static final String SCHEME_NAME = "dhcpl2relay";
    private static final DefaultAnnotations DEVICE_ANNOTATIONS = DefaultAnnotations.builder()
            .set(AnnotationKeys.PROTOCOL, SCHEME_NAME.toUpperCase()).build();

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
        dhcpL2Relay.subsService = new MockSubService();
        dhcpL2Relay.hostService = new MockHostService();
        dhcpL2Relay.mastershipService = new MockMastershipService();
        TestUtils.setField(dhcpL2Relay, "eventDispatcher", new TestEventDispatcher());
        dhcpL2Relay.activate(new ComponentContextAdapter());
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
        System.out.println("Sending pakcet");
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
        System.out.println("Sending pakcet");
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
        System.out.println("Sending pakcet");
        Ethernet offerPacket = constructDhcpOfferPacket(MacAddress.valueOf("bb:bb:bb:bb:bb:bb"),
                CLIENT_MAC, "1.1.1.1", "2.2.2.2");

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

        Ethernet ackPacket = constructDhcpAckPacket(MacAddress.valueOf("bb:bb:bb:bb:bb:bb"),
                CLIENT_MAC, "1.1.1.1", "2.2.2.2");

        sendPacket(ackPacket, ConnectPoint.deviceConnectPoint(OLT_DEV_ID + "/" + 1));

        Ethernet ackRelayed = (Ethernet) getPacket();
        compareServerPackets(ackPacket, ackRelayed);
    }

    public void compareClientPackets(Ethernet sent, Ethernet relayed) {
        sent.setSourceMACAddress(OLT_MAC_ADDRESS);
        sent.setQinQVID(CLIENT_S_TAG.toShort());
        sent.setVlanID(CLIENT_C_TAG.toShort());

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
        sent.setQinQVID(CLIENT_S_TAG.toShort());
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

    private class MockDevice extends DefaultDevice {

        public MockDevice(ProviderId providerId, DeviceId id, Type type,
                          String manufacturer, String hwVersion, String swVersion,
                          String serialNumber, ChassisId chassisId, Annotations... annotations) {
            super(providerId, id, type, manufacturer, hwVersion, swVersion, serialNumber,
                    chassisId, annotations);
        }
    }

    private class MockDeviceService extends DeviceServiceAdapter {

        private ProviderId providerId = new ProviderId("of", "foo");
        private final Device device1 = new MockDevice(providerId, DEVICE_ID_1, Device.Type.SWITCH,
                "foo.inc", "0", "0", OLT_DEV_ID, new ChassisId(),
                DEVICE_ANNOTATIONS);

        @Override
        public Device getDevice(DeviceId devId) {
            return device1;

        }

        @Override
        public Port getPort(ConnectPoint cp) {
            return new MockPort();
        }

        @Override
        public boolean isAvailable(DeviceId d) {
            return true;
        }
    }

    private class  MockPort implements Port {

        @Override
        public boolean isEnabled() {
            return true;
        }
        @Override
        public long portSpeed() {
            return 1000;
        }
        @Override
        public Element element() {
            return null;
        }
        @Override
        public PortNumber number() {
            return null;
        }
        @Override
        public Annotations annotations() {
            return new MockAnnotations();
        }
        @Override
        public Type type() {
            return Port.Type.FIBER;
        }

        private class MockAnnotations implements Annotations {

            @Override
            public String value(String val) {
                return "PON 1/1";
            }
            @Override
            public Set<String> keys() {
                return null;
            }
        }
    }

    private class MockSubService implements SubscriberAndDeviceInformationService {
        MockSubscriberAndDeviceInformation device =
                new MockSubscriberAndDeviceInformation(OLT_DEV_ID, VlanId.NONE, VlanId.NONE, null, null,
                        OLT_MAC_ADDRESS, Ip4Address.valueOf("10.10.10.10"));
        MockSubscriberAndDeviceInformation sub =
                new MockSubscriberAndDeviceInformation(CLIENT_NAS_PORT_ID, CLIENT_C_TAG,
                        CLIENT_S_TAG, CLIENT_NAS_PORT_ID, CLIENT_CIRCUIT_ID, null, null);
        @Override
        public SubscriberAndDeviceInformation get(String id) {
            if (id.equals(OLT_DEV_ID)) {
                return device;
            } else {
                return  sub;
            }
        }

        @Override
        public void invalidateAll() {}
        @Override
        public void invalidateId(String id) {}
        @Override
        public SubscriberAndDeviceInformation getfromCache(String id) {
            return null;
        }
    }

    private class MockMastershipService extends MastershipServiceAdapter {
        @Override
        public boolean isLocalMaster(DeviceId d) {
            return true;
        }
    }

    private class MockSubscriberAndDeviceInformation extends SubscriberAndDeviceInformation {

        MockSubscriberAndDeviceInformation(String id, VlanId ctag,
                                           VlanId stag, String nasPortId,
                                           String circuitId, MacAddress hardId,
                                           Ip4Address ipAddress) {
            this.setCTag(ctag);
            this.setHardwareIdentifier(hardId);
            this.setId(id);
            this.setIPAddress(ipAddress);
            this.setSTag(stag);
            this.setNasPortId(nasPortId);
            this.setCircuitId(circuitId);
        }
    }

    private class MockHostService extends HostServiceAdapter {

        @Override
        public Set<Host> getHostsByMac(MacAddress mac) {

            HostLocation loc = new HostLocation(DEVICE_ID_1, PortNumber.portNumber(22), 0);

            IpAddress ip = IpAddress.valueOf("10.100.200.10");

            Host h = new DefaultHost(ProviderId.NONE, HostId.hostId(mac, VlanId.NONE),
                    mac, VlanId.NONE, loc, ImmutableSet.of(ip));

            return ImmutableSet.of(h);
        }
    }


    /**
     * Mocks the AAAConfig class to force usage of an unroutable address for the
     * RADIUS server.
     */
    static class MockDhcpL2RealyConfig extends DhcpL2RelayConfig {
        @Override
        public Set<ConnectPoint> getDhcpServerConnectPoint() {
            return ImmutableSet.of(SERVER_CONNECT_POINT);
        }

        @Override
        public boolean getModifySrcDstMacAddresses() {
            return true;
        }
    }

    /**
     * Mocks the network config registry.
     */
    @SuppressWarnings("unchecked")
    private static final class TestNetworkConfigRegistry
            extends NetworkConfigRegistryAdapter {
        @Override
        public <S, C extends Config<S>> C getConfig(S subject, Class<C> configClass) {
            DhcpL2RelayConfig dhcpConfig = new MockDhcpL2RealyConfig();
            return (C) dhcpConfig;
        }
    }
}

















