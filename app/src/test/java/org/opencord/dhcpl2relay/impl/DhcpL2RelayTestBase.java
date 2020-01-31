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

import static com.google.common.base.Preconditions.checkState;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.TimeUnit;

import com.google.common.collect.ImmutableSet;
import org.onlab.packet.BasePacket;
import org.onlab.packet.ChassisId;
import org.onlab.packet.DHCP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.IpAddress;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.MacAddress;
import org.onlab.packet.UDP;
import org.onlab.packet.VlanId;
import org.onlab.packet.dhcp.DhcpOption;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreServiceAdapter;
import org.onosproject.core.DefaultApplicationId;
import org.onosproject.event.DefaultEventSinkRegistry;
import org.onosproject.event.Event;
import org.onosproject.event.EventDeliveryService;
import org.onosproject.event.EventSink;
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
import org.onosproject.net.device.DeviceServiceAdapter;
import org.onosproject.net.host.HostServiceAdapter;
import org.onosproject.net.packet.DefaultInboundPacket;
import org.onosproject.net.packet.DefaultPacketContext;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketServiceAdapter;
import org.onosproject.net.provider.ProviderId;
import org.opencord.sadis.BandwidthProfileInformation;
import org.opencord.sadis.BaseInformationService;
import org.opencord.sadis.SadisService;
import org.opencord.sadis.SubscriberAndDeviceInformation;
import org.opencord.sadis.UniTagInformation;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.ComponentInstance;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Common methods for AAA app testing.
 */
public class DhcpL2RelayTestBase {
    private final Logger log = LoggerFactory.getLogger(getClass());

    static final VlanId CLIENT_C_TAG = VlanId.vlanId((short) 2);
    static final VlanId CLIENT_S_TAG = VlanId.vlanId((short) 4);
    static final short CLIENT_C_PBIT = 7;
    static final String CLIENT_ID_1 = "SUBSCRIBER_ID_1";
    static final String CLIENT_NAS_PORT_ID = "PON 1/1";
    static final String CLIENT_CIRCUIT_ID = "CIR-PON 1/1";
    static final short NOT_PROVIDED = 0;

    static final MacAddress CLIENT_MAC = MacAddress.valueOf("00:00:00:00:00:01");
    static final MacAddress SERVER_MAC = MacAddress.valueOf("bb:bb:bb:bb:bb:bb");
    static final String DESTINATION_ADDRESS_IP = "1.1.1.1";
    static final String DHCP_CLIENT_IP_ADDRESS = "2.2.2.2";
    static final int UPLINK_PORT = 5;

    static final String EXPECTED_IP = "10.2.0.2";
    static final String OLT_DEV_ID = "of:00000000000000aa";
    static final DeviceId DEVICE_ID_1 = DeviceId.deviceId(OLT_DEV_ID);
    static final int TRANSACTION_ID = 1000;
    static final String SCHEME_NAME = "dhcpl2relay";
    static final MacAddress OLT_MAC_ADDRESS = MacAddress.valueOf("01:02:03:04:05:06");

    static final ConnectPoint SERVER_CONNECT_POINT =
            ConnectPoint.deviceConnectPoint("of:00000000000000aa/5");

    static final DefaultAnnotations DEVICE_ANNOTATIONS = DefaultAnnotations.builder()
            .set(AnnotationKeys.PROTOCOL, SCHEME_NAME.toUpperCase()).build();

    List<BasePacket> savedPackets = new LinkedList<>();
    PacketProcessor packetProcessor;


    /**
     * Saves the given packet onto the saved packets list.
     *
     * @param packet packet to save
     */
    void savePacket(BasePacket packet) {
        savedPackets.add(packet);
    }

    BasePacket getPacket() {
        return savedPackets.remove(0);
    }

    /**
     * Mock core service adaptor that provides an appId.
     */
    class MockCoreServiceAdapter extends CoreServiceAdapter {

        @Override
        public ApplicationId registerApplication(String name) {
            return new DefaultApplicationId(10, name);
        }
    }

    class MockDeviceService extends DeviceServiceAdapter {

        private ProviderId providerId = new ProviderId("of", "foo");
        private final Device device1 = new DhcpL2RelayTestBase.MockDevice(providerId, DEVICE_ID_1, Device.Type.SWITCH,
                "foo.inc", "0", "0", OLT_DEV_ID, new ChassisId(),
                DEVICE_ANNOTATIONS);

        @Override
        public Device getDevice(DeviceId devId) {
            return device1;

        }

        @Override
        public Port getPort(ConnectPoint cp) {
            return new DhcpL2RelayTestBase.MockPort();
        }

        @Override
        public Port getPort(DeviceId deviceId, PortNumber portNumber) {
            return new DhcpL2RelayTestBase.MockPort();
        }

        @Override
        public boolean isAvailable(DeviceId d) {
            return true;
        }
    }

    class MockDevice extends DefaultDevice {

        public MockDevice(ProviderId providerId, DeviceId id, Type type,
                          String manufacturer, String hwVersion, String swVersion,
                          String serialNumber, ChassisId chassisId, Annotations... annotations) {
            super(providerId, id, type, manufacturer, hwVersion, swVersion, serialNumber,
                    chassisId, annotations);
        }
    }

    class MockHostService extends HostServiceAdapter {

        @Override
        public Set<Host> getHostsByMac(MacAddress mac) {

            HostLocation loc = new HostLocation(DEVICE_ID_1, PortNumber.portNumber(22), 0);

            IpAddress ip = IpAddress.valueOf("10.100.200.10");

            Host h = new DefaultHost(ProviderId.NONE, HostId.hostId(mac, VlanId.NONE),
                    mac, VlanId.NONE, loc, ImmutableSet.of(ip));

            return ImmutableSet.of(h);
        }
    }

    class MockMastershipService extends MastershipServiceAdapter {
        @Override
        public boolean isLocalMaster(DeviceId d) {
            return true;
        }
    }

    class  MockPort implements Port {

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

    /**
     * Keeps a reference to the PacketProcessor and saves the OutboundPackets.
     */
    class MockPacketService extends PacketServiceAdapter {

        @Override
        public void addProcessor(PacketProcessor processor, int priority) {
            packetProcessor = processor;
        }

        @Override
        public void emit(OutboundPacket packet) {
            try {
                Ethernet eth = Ethernet.deserializer().deserialize(packet.data().array(),
                        0, packet.data().array().length);
                savePacket(eth);
            } catch (Exception e) {
                fail(e.getMessage());
            }
        }
    }

    class MockSadisService implements SadisService {
        @Override
        public BaseInformationService<SubscriberAndDeviceInformation> getSubscriberInfoService() {
            return new DhcpL2RelayTestBase.MockSubService();
        }

        @Override
        public BaseInformationService<BandwidthProfileInformation> getBandwidthProfileService() {
            return null;
        }
    }

    class MockSubService implements BaseInformationService<SubscriberAndDeviceInformation> {
        DhcpL2RelayTestBase.MockSubscriberAndDeviceInformation device =
                new DhcpL2RelayTestBase.MockSubscriberAndDeviceInformation(OLT_DEV_ID, VlanId.NONE, VlanId.NONE, null,
                        null, OLT_MAC_ADDRESS, Ip4Address.valueOf("10.10.10.10"), UPLINK_PORT);
        DhcpL2RelayTestBase.MockSubscriberAndDeviceInformation sub =
                new DhcpL2RelayTestBase.MockSubscriberAndDeviceInformation(CLIENT_ID_1, CLIENT_C_TAG,
                        CLIENT_S_TAG, CLIENT_NAS_PORT_ID, CLIENT_CIRCUIT_ID, null, null, -1);
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

    class MockSubscriberAndDeviceInformation extends SubscriberAndDeviceInformation {

        MockSubscriberAndDeviceInformation(String id, VlanId cTag,
                                           VlanId sTag, String nasPortId,
                                           String circuitId, MacAddress hardId,
                                           Ip4Address ipAddress, int uplinkPort) {
            this.setHardwareIdentifier(hardId);
            this.setId(id);
            this.setIPAddress(ipAddress);
            this.setNasPortId(nasPortId);
            this.setCircuitId(circuitId);
            this.setUplinkPort(uplinkPort);

            List<UniTagInformation> uniTagInformationList = new ArrayList<>();

            UniTagInformation uniTagInformation = new UniTagInformation.Builder()
                    .setPonCTag(cTag)
                    .setPonSTag(sTag)
                    .setUsPonCTagPriority(CLIENT_C_PBIT)
                    .setIsDhcpRequired(true)
                    .build();
            uniTagInformationList.add(uniTagInformation);
            this.setUniTagList(uniTagInformationList);
        }
    }

    class MockComponentContext implements ComponentContext {

        @Override
        public Dictionary<String, Object> getProperties() {
            Dictionary<String, Object> cfgDict = new Hashtable<String, Object>();
            cfgDict.put("publishCountersRate", 10);
            return cfgDict;
        }

        @Override
        public Object locateService(String name) {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public Object locateService(String name, ServiceReference reference) {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public Object[] locateServices(String name) {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public BundleContext getBundleContext() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public Bundle getUsingBundle() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public ComponentInstance getComponentInstance() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public void enableComponent(String name) {
            // TODO Auto-generated method stub
        }

        @Override
        public void disableComponent(String name) {
            // TODO Auto-generated method stub
        }

        @Override
        public ServiceReference getServiceReference() {
            // TODO Auto-generated method stub
            return null;
        }
    }


    /**
     * Mocks the DefaultPacketContext.
     */
    final class TestPacketContext extends DefaultPacketContext {

        private TestPacketContext(long time, InboundPacket inPkt,
                                  OutboundPacket outPkt, boolean block) {
            super(time, inPkt, outPkt, block);
        }

        @Override
        public void send() {
            // We don't send anything out.
        }
    }

    public static class TestEventDispatcher extends DefaultEventSinkRegistry
            implements EventDeliveryService {
        @Override
        @SuppressWarnings("unchecked")
        public synchronized void post(Event event) {
            EventSink sink = getSink(event.getClass());
            checkState(sink != null, "No sink for event %s", event);
            sink.process(event);
        }

        @Override
        public void setDispatchTimeLimit(long millis) {
        }

        @Override
        public long getDispatchTimeLimit() {
            return 0;
        }
    }

    /**
     * Creates a mock object for a scheduled executor service.
     *
     */
    public static final class MockExecutor implements ScheduledExecutorService {
        private ScheduledExecutorService executor;

        MockExecutor(ScheduledExecutorService executor) {
            this.executor = executor;
        }

        String lastMethodCalled = "";
        long lastInitialDelay;
        long lastDelay;
        TimeUnit lastUnit;

        public void assertLastMethodCalled(String method, long initialDelay, long delay, TimeUnit unit) {
            assertEquals(method, lastMethodCalled);
            assertEquals(initialDelay, lastInitialDelay);
            assertEquals(delay, lastDelay);
            assertEquals(unit, lastUnit);
        }

        @Override
        public ScheduledFuture<?> schedule(Runnable command, long delay, TimeUnit unit) {
            lastMethodCalled = "scheduleRunnable";
            lastDelay = delay;
            lastUnit = unit;
            return null;
        }

        @Override
        public <V> ScheduledFuture<V> schedule(Callable<V> callable, long delay, TimeUnit unit) {
            lastMethodCalled = "scheduleCallable";
            lastDelay = delay;
            lastUnit = unit;
            return null;
        }

        @Override
        public ScheduledFuture<?> scheduleAtFixedRate(
                Runnable command, long initialDelay, long period, TimeUnit unit) {
            lastMethodCalled = "scheduleAtFixedRate";
            lastInitialDelay = initialDelay;
            lastDelay = period;
            lastUnit = unit;
            return null;
        }

        @Override
        public ScheduledFuture<?> scheduleWithFixedDelay(
                Runnable command, long initialDelay, long delay, TimeUnit unit) {
            lastMethodCalled = "scheduleWithFixedDelay";
            lastInitialDelay = initialDelay;
            lastDelay = delay;
            lastUnit = unit;
            command.run();
            return null;
        }

        @Override
        public boolean awaitTermination(long timeout, TimeUnit unit) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <T> List<Future<T>> invokeAll(Collection<? extends Callable<T>> tasks)
                throws InterruptedException {
            throw new UnsupportedOperationException();
        }

        @Override
        public <T> List<Future<T>> invokeAll(
                Collection<? extends Callable<T>> tasks, long timeout, TimeUnit unit)
                throws InterruptedException {
            throw new UnsupportedOperationException();
        }

        @Override
        public <T> T invokeAny(Collection<? extends Callable<T>> tasks)
                throws ExecutionException, InterruptedException {
            throw new UnsupportedOperationException();
        }

        @Override
        public <T> T invokeAny(Collection<? extends Callable<T>> tasks, long timeout, TimeUnit unit)
                throws ExecutionException, InterruptedException, TimeoutException {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isShutdown() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isTerminated() {
            throw new UnsupportedOperationException();
        }

        @Override
        public void shutdown() {
            throw new UnsupportedOperationException();
        }

        @Override
        public List<Runnable> shutdownNow() {
            return null;
        }

        @Override
        public <T> Future<T> submit(Callable<T> task) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Future<?> submit(Runnable task) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <T> Future<T> submit(Runnable task, T result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void execute(Runnable command) {
            throw new UnsupportedOperationException();
        }
    }

    /**
     * Sends an Ethernet packet to the process method of the Packet Processor.
     *
     * @param pkt Ethernet packet
     */
    void sendPacket(Ethernet pkt, ConnectPoint cp) {
        final ByteBuffer byteBuffer = ByteBuffer.wrap(pkt.serialize());
        InboundPacket inPacket = new DefaultInboundPacket(cp, pkt, byteBuffer);

        PacketContext context = new TestPacketContext(127L, inPacket, null, false);
        packetProcessor.process(context);
    }

    /**
     * Constructs an Ethernet packet with IP/UDP/DHCP payload.
     *
     * @return Ethernet packet
     */
    private Ethernet construcEthernetPacket(MacAddress srcMac, MacAddress dstMac,
                                                String dstIp, byte dhcpReqRsp,
                                                MacAddress clientHwAddress,
                                                Ip4Address dhcpClientIpAddress) {
        // Ethernet Frame.
        Ethernet ethPkt = new Ethernet();
        ethPkt.setSourceMACAddress(srcMac);
        ethPkt.setDestinationMACAddress(dstMac);
        ethPkt.setEtherType(Ethernet.TYPE_IPV4);
        ethPkt.setVlanID(CLIENT_C_TAG.toShort());
        ethPkt.setPriorityCode((byte) CLIENT_C_PBIT);

        if (DHCP.OPCODE_REPLY == dhcpReqRsp) {
            ethPkt.setQinQPriorityCode((byte) 3);
            ethPkt.setQinQVID((short) 4);
        }

        // IP Packet
        IPv4 ipv4Reply = new IPv4();
        ipv4Reply.setSourceAddress(0);
        ipv4Reply.setDestinationAddress(dstIp);

        ipv4Reply.setTtl((byte) 127);

        // UDP Datagram.
        UDP udpReply = new UDP();
        udpReply.setSourcePort((byte) UDP.DHCP_CLIENT_PORT);
        udpReply.setDestinationPort((byte) UDP.DHCP_SERVER_PORT);

        // DHCP Payload.
        DHCP dhcpReply = new DHCP();
        dhcpReply.setOpCode(dhcpReqRsp);

        dhcpReply.setYourIPAddress(dhcpClientIpAddress.toInt());
        dhcpReply.setServerIPAddress(0);

        final byte[] serverNameBytes = new byte[64];
        String result = new String(serverNameBytes, StandardCharsets.US_ASCII).trim();
        dhcpReply.setServerName(result);

        final byte[] bootFileBytes = new byte[128];
        String result1 = new String(bootFileBytes, StandardCharsets.US_ASCII).trim();
        dhcpReply.setBootFileName(result1);

        dhcpReply.setTransactionId(TRANSACTION_ID);
        dhcpReply.setClientHardwareAddress(clientHwAddress.toBytes());
        dhcpReply.setHardwareType(DHCP.HWTYPE_ETHERNET);
        dhcpReply.setHardwareAddressLength((byte) 6);

        udpReply.setPayload(dhcpReply);
        ipv4Reply.setPayload(udpReply);
        ethPkt.setPayload(ipv4Reply);

        return ethPkt;
    }

    /**
     * Constructs DHCP Discover Packet.
     *
     * @return Ethernet packet
     */
    Ethernet constructDhcpDiscoverPacket(MacAddress clientMac) {

        Ethernet pkt = construcEthernetPacket(clientMac, MacAddress.BROADCAST,
                "255.255.255.255", DHCP.OPCODE_REQUEST, MacAddress.NONE,
                Ip4Address.valueOf("0.0.0.0"));

        IPv4 ipv4Packet = (IPv4) pkt.getPayload();
        UDP udpPacket = (UDP) ipv4Packet.getPayload();
        DHCP dhcpPacket = (DHCP) udpPacket.getPayload();

        dhcpPacket.setOptions(constructDhcpOptions(DHCP.MsgType.DHCPDISCOVER));

        return pkt;
    }

    /**
     * Constructs DHCP Request Packet.
     *
     * @return Ethernet packet
     */
    Ethernet constructDhcpRequestPacket(MacAddress clientMac) {

        Ethernet pkt = construcEthernetPacket(clientMac, MacAddress.BROADCAST,
                "255.255.255.255", DHCP.OPCODE_REQUEST, MacAddress.NONE,
                Ip4Address.valueOf("0.0.0.0"));

        IPv4 ipv4Packet = (IPv4) pkt.getPayload();
        UDP udpPacket = (UDP) ipv4Packet.getPayload();
        DHCP dhcpPacket = (DHCP) udpPacket.getPayload();

        dhcpPacket.setOptions(constructDhcpOptions(DHCP.MsgType.DHCPREQUEST));

        return pkt;
    }

    /**
     * Constructs DHCP Offer Packet.
     *
     * @return Ethernet packet
     */
    Ethernet constructDhcpOfferPacket(MacAddress servMac, MacAddress clientMac,
                                           String ipAddress, String dhcpClientIpAddress) {

        Ethernet pkt = construcEthernetPacket(servMac, clientMac, ipAddress, DHCP.OPCODE_REPLY,
                clientMac, Ip4Address.valueOf(dhcpClientIpAddress));

        IPv4 ipv4Packet = (IPv4) pkt.getPayload();
        UDP udpPacket = (UDP) ipv4Packet.getPayload();
        DHCP dhcpPacket = (DHCP) udpPacket.getPayload();

        dhcpPacket.setOptions(constructDhcpOptions(DHCP.MsgType.DHCPOFFER));

        return pkt;
    }

    /**
     * Constructs DHCP Ack Packet.
     *
     * @return Ethernet packet
     */
    Ethernet constructDhcpAckPacket(MacAddress servMac, MacAddress clientMac,
                                           String ipAddress, String dhcpClientIpAddress) {

        Ethernet pkt = construcEthernetPacket(servMac, clientMac, ipAddress, DHCP.OPCODE_REPLY,
                clientMac, Ip4Address.valueOf(dhcpClientIpAddress));

        IPv4 ipv4Packet = (IPv4) pkt.getPayload();
        UDP udpPacket = (UDP) ipv4Packet.getPayload();
        DHCP dhcpPacket = (DHCP) udpPacket.getPayload();

        dhcpPacket.setOptions(constructDhcpOptions(DHCP.MsgType.DHCPACK));

        return pkt;
    }

    /**
     * Constructs DHCP Discover Options.
     *
     * @return Ethernet packet
     */
    private List<DhcpOption> constructDhcpOptions(DHCP.MsgType packetType) {

        // DHCP Options.
        DhcpOption option = new DhcpOption();
        List<DhcpOption> optionList = new ArrayList<>();


        // DHCP Message Type.
        option.setCode(DHCP.DHCPOptionCode.OptionCode_MessageType.getValue());
        option.setLength((byte) 1);
        byte[] optionData = {(byte) packetType.getValue()};
        option.setData(optionData);
        optionList.add(option);

        // DHCP Requested IP.
        option = new DhcpOption();
        option.setCode(DHCP.DHCPOptionCode.OptionCode_RequestedIP.getValue());
        option.setLength((byte) 4);
        optionData = Ip4Address.valueOf(EXPECTED_IP).toOctets();
        option.setData(optionData);
        optionList.add(option);

        // End Option.
        option = new DhcpOption();
        option.setCode(DHCP.DHCPOptionCode.OptionCode_END.getValue());
        option.setLength((byte) 1);
        optionList.add(option);

        return optionList;
    }
}