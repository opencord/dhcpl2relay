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

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Modified;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.DeserializationException;
import org.onlab.packet.DHCP;
import org.onlab.packet.DHCPOption;
import org.onlab.packet.DHCPPacketType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IPv4;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
import org.onlab.packet.VlanId;
import org.onosproject.mastership.MastershipEvent;
import org.onosproject.mastership.MastershipListener;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.opencord.dhcpl2relay.packet.DhcpEthernet;
import org.opencord.dhcpl2relay.packet.DhcpOption82;
import org.onlab.util.Tools;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.AnnotationKeys;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Host;
import org.onosproject.net.Port;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;

import org.opencord.sadis.SubscriberAndDeviceInformation;
import org.opencord.sadis.SubscriberAndDeviceInformationService;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.Dictionary;
import java.util.Map;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static org.onlab.packet.DHCP.DHCPOptionCode.OptionCode_MessageType;
import static org.onlab.packet.MacAddress.valueOf;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;

/**
 * DHCP Relay Agent Application Component.
 */
@Component(immediate = true)
public class DhcpL2Relay {

    public static final String DHCP_L2RELAY_APP = "org.opencord.dhcpl2relay";
    private final Logger log = LoggerFactory.getLogger(getClass());
    private final InternalConfigListener cfgListener =
            new InternalConfigListener();

    private final Set<ConfigFactory> factories = ImmutableSet.of(
            new ConfigFactory<ApplicationId, DhcpL2RelayConfig>(APP_SUBJECT_FACTORY,
                    DhcpL2RelayConfig.class,
                    "dhcpl2relay") {
                @Override
                public DhcpL2RelayConfig createConfig() {
                    return new DhcpL2RelayConfig();
                }
            }
    );

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected NetworkConfigRegistry cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected ComponentConfigService componentConfigService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected SubscriberAndDeviceInformationService subsService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected MastershipService mastershipService;

    @Property(name = "option82", boolValue = true,
            label = "Add option 82 to relayed packets")
    protected boolean option82 = true;

    @Property(name = "enableDhcpBroadcastReplies", boolValue = false,
            label = "Add option 82 to relayed packets")
    protected boolean enableDhcpBroadcastReplies = false;

    private DhcpRelayPacketProcessor dhcpRelayPacketProcessor =
            new DhcpRelayPacketProcessor();

    private InnerMastershipListener changeListener = new InnerMastershipListener();
    private InnerDeviceListener deviceListener = new InnerDeviceListener();

    // connect points to the DHCP server
    Set<ConnectPoint> dhcpConnectPoints;
    private AtomicReference<ConnectPoint> dhcpServerConnectPoint = new AtomicReference<>();
    private MacAddress dhcpConnectMac = MacAddress.BROADCAST;
    private ApplicationId appId;

    static Map<String, DhcpAllocationInfo> allocationMap = Maps.newConcurrentMap();

    @Activate
    protected void activate(ComponentContext context) {
        //start the dhcp relay agent
        appId = coreService.registerApplication(DHCP_L2RELAY_APP);
        componentConfigService.registerProperties(getClass());

        cfgService.addListener(cfgListener);
        mastershipService.addListener(changeListener);
        deviceService.addListener(deviceListener);

        factories.forEach(cfgService::registerConfigFactory);
        //update the dhcp server configuration.
        updateConfig();
        //add the packet services.
        packetService.addProcessor(dhcpRelayPacketProcessor,
                PacketProcessor.director(0));
        requestDhcpPackets();
        if (context != null) {
            modified(context);
        }

        log.info("DHCP-L2-RELAY Started");
    }

    @Deactivate
    protected void deactivate() {
        cfgService.removeListener(cfgListener);
        factories.forEach(cfgService::unregisterConfigFactory);
        packetService.removeProcessor(dhcpRelayPacketProcessor);
        cancelDhcpPackets();

        componentConfigService.unregisterProperties(getClass(), false);

        log.info("DHCP-L2-RELAY Stopped");
    }

    @Modified
    protected void modified(ComponentContext context) {

        Dictionary<?, ?> properties = context.getProperties();

        Boolean o = Tools.isPropertyEnabled(properties, "option82");
        if (o != null) {
            option82 = o;
        }
    }

    /**
     * Checks if this app has been configured.
     *
     * @return true if all information we need have been initialized
     */
    private boolean configured() {
        return dhcpServerConnectPoint.get() != null;
    }

    /**
     * Selects a connect point through an available device for which it is the master.
     */
    private void selectServerConnectPoint() {
        synchronized (this) {
            dhcpServerConnectPoint.set(null);
            if (dhcpConnectPoints != null) {
                // find a connect point through a device for which we are master
                for (ConnectPoint cp: dhcpConnectPoints) {
                    if (mastershipService.isLocalMaster(cp.deviceId())) {
                        if (deviceService.isAvailable(cp.deviceId())) {
                            dhcpServerConnectPoint.set(cp);
                        }
                        log.info("DHCP connectPoint selected is {}", cp);
                        break;
                    }
                }
            }

            log.info("DHCP Server connectPoint is {}", dhcpServerConnectPoint.get());

            if (dhcpServerConnectPoint.get() == null) {
                log.error("Master of none, can't relay DHCP Message to server");
            }
        }
    }

    /**
     * Updates the network configuration.
     */
    private void updateConfig() {
        DhcpL2RelayConfig cfg = cfgService.getConfig(appId, DhcpL2RelayConfig.class);
        if (cfg == null) {
            log.warn("Dhcp Server info not available");
            return;
        }

        dhcpConnectPoints = Sets.newConcurrentHashSet(cfg.getDhcpServerConnectPoint());

        selectServerConnectPoint();

        log.info("dhcp server connect point: " + dhcpServerConnectPoint);
    }

    /**
     * Request DHCP packet in via PacketService.
     */
    private void requestDhcpPackets() {
        TrafficSelector.Builder selectorServer = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_UDP)
                .matchUdpSrc(TpPort.tpPort(UDP.DHCP_SERVER_PORT));
        packetService.requestPackets(selectorServer.build(),
                PacketPriority.CONTROL, appId);

        TrafficSelector.Builder selectorClient = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_UDP)
                .matchUdpSrc(TpPort.tpPort(UDP.DHCP_CLIENT_PORT));
        packetService.requestPackets(selectorClient.build(),
                PacketPriority.CONTROL, appId);

    }

    /**
     * Cancel requested DHCP packets in via packet service.
     */
    private void cancelDhcpPackets() {
        TrafficSelector.Builder selectorServer = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_UDP)
                .matchUdpSrc(TpPort.tpPort(UDP.DHCP_SERVER_PORT));
        packetService.cancelPackets(selectorServer.build(),
                PacketPriority.CONTROL, appId);

        TrafficSelector.Builder selectorClient = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_UDP)
                .matchUdpSrc(TpPort.tpPort(UDP.DHCP_CLIENT_PORT));
        packetService.cancelPackets(selectorClient.build(),
                PacketPriority.CONTROL, appId);
    }

    public static Map<String, DhcpAllocationInfo> allocationMap() {
        return allocationMap;
    }

    private SubscriberAndDeviceInformation getDevice(PacketContext context) {
        String serialNo = deviceService.getDevice(context.inPacket().
                receivedFrom().deviceId()).serialNumber();

        return subsService.get(serialNo);
    }

    private SubscriberAndDeviceInformation getDevice(ConnectPoint cp) {
        String serialNo = deviceService.getDevice(cp.deviceId()).
                serialNumber();

        return subsService.get(serialNo);
    }

    private MacAddress relayAgentMacAddress(PacketContext context) {

        SubscriberAndDeviceInformation device = this.getDevice(context);
        if (device == null) {
            log.warn("Device not found for {}", context.inPacket().
                    receivedFrom());
            return null;
        }

        return device.hardwareIdentifier();
    }

    private String nasPortId(PacketContext context) {
        return nasPortId(context.inPacket().receivedFrom());
    }

    private String nasPortId(ConnectPoint cp) {
        Port p = deviceService.getPort(cp);
        return p.annotations().value(AnnotationKeys.PORT_NAME);
    }

    private SubscriberAndDeviceInformation getSubscriber(PacketContext context) {
        return subsService.get(nasPortId(context));
    }

    private VlanId cTag(PacketContext context) {
        SubscriberAndDeviceInformation sub = getSubscriber(context);
        if (sub == null) {
            log.warn("Subscriber info not found for {}", context.inPacket().
                    receivedFrom());
            return VlanId.NONE;
        }
        return sub.cTag();
    }

    private VlanId cTag(ConnectPoint cp) {
        String portId = nasPortId(cp);
        SubscriberAndDeviceInformation sub = subsService.get(portId);
        if (sub == null) {
            log.warn("Subscriber info not found for {} looking for C-TAG", cp);
            return VlanId.NONE;
        }
        return sub.cTag();
    }

    private VlanId sTag(ConnectPoint cp) {
        String portId = nasPortId(cp);
        SubscriberAndDeviceInformation sub = subsService.get(portId);
        if (sub == null) {
            log.warn("Subscriber info not found for {} looking for S-TAG", cp);
            return VlanId.NONE;
        }
        return sub.sTag();
    }

    private VlanId sTag(PacketContext context) {
        SubscriberAndDeviceInformation sub = getSubscriber(context);
        if (sub == null) {
            log.warn("Subscriber info not found for {}", context.inPacket().
                    receivedFrom());
            return VlanId.NONE;
        }
        return sub.sTag();
    }

    private class DhcpRelayPacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            if (!configured()) {
                log.warn("Missing DHCP relay config. Abort packet processing");
                return;
            }

            // process the packet and get the payload
            DhcpEthernet packet = null;
            ByteBuffer byteBuffer = context.inPacket().unparsed();
            try {
                packet = DhcpEthernet.deserializer().deserialize(byteBuffer.array(), 0, byteBuffer.array().length);
            } catch (DeserializationException e) {
                log.warn("Unable to deserialize packet");
            }

            if (packet == null) {
                log.warn("Packet is null");
                return;
            }

            log.debug("Got a packet ", packet);

            if (packet.getEtherType() == DhcpEthernet.TYPE_IPV4) {
                IPv4 ipv4Packet = (IPv4) packet.getPayload();

                if (ipv4Packet.getProtocol() == IPv4.PROTOCOL_UDP) {
                    UDP udpPacket = (UDP) ipv4Packet.getPayload();
                    if (udpPacket.getSourcePort() == UDP.DHCP_CLIENT_PORT ||
                            udpPacket.getSourcePort() == UDP.DHCP_SERVER_PORT) {
                        DHCP dhcpPayload = (DHCP) udpPacket.getPayload();
                        //This packet is dhcp.
                        processDhcpPacket(context, packet, dhcpPayload);
                    }
                }
            }
        }

        //forward the packet to ConnectPoint where the DHCP server is attached.
        private void forwardPacket(DhcpEthernet packet) {

            if (dhcpServerConnectPoint.get() != null) {
                TrafficTreatment t = DefaultTrafficTreatment.builder()
                        .setOutput(dhcpServerConnectPoint.get().port()).build();
                OutboundPacket o = new DefaultOutboundPacket(
                        dhcpServerConnectPoint.get().deviceId(), t,
                        ByteBuffer.wrap(packet.serialize()));
                if (log.isTraceEnabled()) {
                log.trace("Relaying packet to dhcp server {} at {}",
                        packet, dhcpServerConnectPoint.get());
                }
                packetService.emit(o);
            } else {
                log.warn("No dhcp server connect point");
            }
        }

        // get the type of the DHCP packet
        private DHCPPacketType getDhcpPacketType(DHCP dhcpPayload) {

            for (DHCPOption option : dhcpPayload.getOptions()) {
                if (option.getCode() == OptionCode_MessageType.getValue()) {
                    byte[] data = option.getData();
                    return DHCPPacketType.getType(data[0]);
                }
            }
            return null;
        }

        //process the dhcp packet before sending to server
        private void processDhcpPacket(PacketContext context, DhcpEthernet packet,
                                       DHCP dhcpPayload) {
            if (dhcpPayload == null) {
                log.warn("DHCP payload is null");
                return;
            }

            DHCPPacketType incomingPacketType = getDhcpPacketType(dhcpPayload);

            log.info("Received DHCP Packet of type {}", incomingPacketType);

            switch (incomingPacketType) {
                case DHCPDISCOVER:
                    DhcpEthernet ethernetPacketDiscover =
                            processDhcpPacketFromClient(context, packet);
                    if (ethernetPacketDiscover != null) {
                        forwardPacket(ethernetPacketDiscover);
                    }
                    break;
                case DHCPOFFER:
                    //reply to dhcp client.
                    DhcpEthernet ethernetPacketOffer = processDhcpPacketFromServer(packet);
                    if (ethernetPacketOffer != null) {
                        sendReply(ethernetPacketOffer, dhcpPayload);
                    }
                    break;
                case DHCPREQUEST:
                    DhcpEthernet ethernetPacketRequest =
                            processDhcpPacketFromClient(context, packet);
                    if (ethernetPacketRequest != null) {
                        forwardPacket(ethernetPacketRequest);
                    }
                    break;
                case DHCPACK:
                    //reply to dhcp client.
                    DhcpEthernet ethernetPacketAck = processDhcpPacketFromServer(packet);
                    if (ethernetPacketAck != null) {
                        sendReply(ethernetPacketAck, dhcpPayload);
                    }
                    break;
                default:
                    break;
            }
        }

        private DhcpEthernet processDhcpPacketFromClient(PacketContext context,
                                                         DhcpEthernet ethernetPacket) {

            MacAddress relayAgentMac = relayAgentMacAddress(context);
            if (relayAgentMac == null) {
                log.warn("RelayAgent MAC not found ");
                return null;
            }

            DhcpEthernet etherReply = ethernetPacket;

            IPv4 ipv4Packet = (IPv4) etherReply.getPayload();
            UDP udpPacket = (UDP) ipv4Packet.getPayload();
            DHCP dhcpPacket = (DHCP) udpPacket.getPayload();

            if (enableDhcpBroadcastReplies) {
                // We want the reply to come back as a L2 broadcast
                dhcpPacket.setFlags((short) 0x8000);
            }

            // remove from the allocation map (used for display) as it's is
            // requesting a fresh allocation
            if (getDhcpPacketType(dhcpPacket) == DHCPPacketType.DHCPREQUEST) {

                String portId = nasPortId(context.inPacket().receivedFrom());
                SubscriberAndDeviceInformation sub = subsService.get(portId);
                if (sub != null) {
                    allocationMap.remove(sub.nasPortId());
                }
            } // end allocation for display

            if (option82) {
                SubscriberAndDeviceInformation entry = getSubscriber(context);
                if (entry == null) {
                    log.info("Dropping packet as subscriber entry is not available");
                    return null;
                }

                DHCP dhcpPacketWithOption82 = addOption82(dhcpPacket, entry);
                udpPacket.setPayload(dhcpPacketWithOption82);
            }

            ipv4Packet.setPayload(udpPacket);
            etherReply.setPayload(ipv4Packet);
            etherReply.setSourceMacAddress(relayAgentMac);
            etherReply.setDestinationMacAddress(dhcpConnectMac);

            etherReply.setPriorityCode(ethernetPacket.getPriorityCode());
            etherReply.setVlanID(cTag(context).toShort());
            etherReply.setQinQtpid(DhcpEthernet.TYPE_VLAN);
            etherReply.setQinQVid(sTag(context).toShort());

            log.info("Finished processing packet -- sending packet {}", etherReply);
            return etherReply;
        }

        //build the DHCP offer/ack with proper client port.
        private DhcpEthernet processDhcpPacketFromServer(DhcpEthernet ethernetPacket) {
            // get dhcp header.
            DhcpEthernet etherReply = (DhcpEthernet) ethernetPacket.clone();
            IPv4 ipv4Packet = (IPv4) etherReply.getPayload();
            UDP udpPacket = (UDP) ipv4Packet.getPayload();
            DHCP dhcpPayload = (DHCP) udpPacket.getPayload();

            MacAddress dstMac = valueOf(dhcpPayload.getClientHardwareAddress());
            ConnectPoint subsCp = getConnectPointOfClient(dstMac);
            // if it's an ACK packet store the information for display purpose
            if (getDhcpPacketType(dhcpPayload) == DHCPPacketType.DHCPACK) {

                String portId = nasPortId(subsCp);
                SubscriberAndDeviceInformation sub = subsService.get(portId);
                if (sub != null) {
                    List<DHCPOption> options = dhcpPayload.getOptions();
                    List<DHCPOption> circuitIds = options.stream()
                            .filter(option -> option.getCode() == DHCP.DHCPOptionCode.OptionCode_CircuitID.getValue())
                            .collect(Collectors.toList());

                    String circuitId = "None";
                    if (circuitIds.size() == 1) {
                        circuitId = circuitIds.get(0).getData().toString();
                    }

                    IpAddress ip = IpAddress.valueOf(dhcpPayload.getYourIPAddress());

                    //storeDHCPAllocationInfo
                    DhcpAllocationInfo info = new DhcpAllocationInfo(circuitId, dstMac, ip);

                    allocationMap.put(sub.nasPortId(), info);
                }
            } // end storing of info

            // we leave the srcMac from the original packet
            etherReply.setDestinationMacAddress(dstMac);
            etherReply.setQinQVid(sTag(subsCp).toShort());
            etherReply.setPriorityCode(ethernetPacket.getPriorityCode());
            etherReply.setVlanID((cTag(subsCp).toShort()));

            if (option82) {
                udpPacket.setPayload(removeOption82(dhcpPayload));
            } else {
                udpPacket.setPayload(dhcpPayload);
            }
            ipv4Packet.setPayload(udpPacket);
            etherReply.setPayload(ipv4Packet);

            log.info("Finished processing packet");
            return etherReply;
        }

        /*
         * Get ConnectPoint of the Client based on it's MAC address
         */
        private ConnectPoint getConnectPointOfClient(MacAddress dstMac) {
            Set<Host> hosts = hostService.getHostsByMac(dstMac);
            if (hosts == null || hosts.isEmpty()) {
                log.warn("Cannot determine host for DHCP client: {}. Aborting "
                        + "relay for dhcp packet from server",
                        dstMac);
                return null;
            }
            for (Host h : hosts) {
                // if more than one,
                // find the connect point which has an valid entry in SADIS
                ConnectPoint cp = new ConnectPoint(h.location().deviceId(),
                        h.location().port());

                if (sTag(cp) != VlanId.NONE) {
                    return cp;
                }
            }

            return null;
        }

        //send the response to the requester host.
        private void sendReply(DhcpEthernet ethPacket, DHCP dhcpPayload) {
            MacAddress descMac = valueOf(dhcpPayload.getClientHardwareAddress());
            ConnectPoint subCp = getConnectPointOfClient(descMac);

            // Send packet out to requester if the host information is available
            if (subCp != null) {
                log.info("Sending DHCP packet to cp: {}", subCp);
                TrafficTreatment t = DefaultTrafficTreatment.builder()
                        .setOutput(subCp.port()).build();
                OutboundPacket o = new DefaultOutboundPacket(
                        subCp.deviceId(), t, ByteBuffer.wrap(ethPacket.serialize()));
                if (log.isTraceEnabled()) {
                    log.trace("Relaying packet to dhcp client {}", ethPacket);
                }
                packetService.emit(o);
                log.info("DHCP Packet sent to {}", subCp);
            } else {
                log.error("Dropping DHCP packet because can't find host for {}", descMac);
            }
        }
    }

    private DHCP addOption82(DHCP dhcpPacket, SubscriberAndDeviceInformation entry) {
        log.debug("option82data {} ", entry);

        List<DHCPOption> options = Lists.newArrayList(dhcpPacket.getOptions());
        DhcpOption82 option82 = new DhcpOption82();
        option82.setAgentCircuitId(entry.circuitId());
        option82.setAgentRemoteId(entry.remoteId());
        DHCPOption option = new DHCPOption()
                                .setCode(DHCP.DHCPOptionCode.OptionCode_CircuitID.getValue())
                                .setData(option82.toByteArray())
                                .setLength(option82.length());

        options.add(options.size() - 1, option);
        dhcpPacket.setOptions(options);

        return dhcpPacket;

    }

    private DHCP removeOption82(DHCP dhcpPacket) {
        List<DHCPOption> options = dhcpPacket.getOptions();
        List<DHCPOption> newoptions = options.stream()
                .filter(option -> option.getCode() != DHCP.DHCPOptionCode.OptionCode_CircuitID.getValue())
                .collect(Collectors.toList());

        return dhcpPacket.setOptions(newoptions);
    }
    /**
     * Listener for network config events.
     */
    private class InternalConfigListener implements NetworkConfigListener {

        @Override
        public void event(NetworkConfigEvent event) {

            if ((event.type() == NetworkConfigEvent.Type.CONFIG_ADDED ||
                    event.type() == NetworkConfigEvent.Type.CONFIG_UPDATED) &&
                    event.configClass().equals(DhcpL2RelayConfig.class)) {
                updateConfig();
                log.info("Reconfigured");
            }
        }
    }

    /**
     * Handles Mastership changes for the devices which connect
     * to the DHCP server.
     */
    private class InnerMastershipListener implements MastershipListener {
        @Override
        public void event(MastershipEvent event) {
            if (dhcpServerConnectPoint.get() != null &&
                    dhcpServerConnectPoint.get().deviceId().
                            equals(event.subject())) {
                log.trace("Mastership Event recevived for {}", event.subject());
                // mastership of the device for our connect point has changed
                // reselect
                selectServerConnectPoint();
            }
        }
    }

    /**
     * Handles Device status change for the devices which connect
     * to the DHCP server.
     */
    private class InnerDeviceListener implements DeviceListener {
        @Override
        public void event(DeviceEvent event) {
            log.trace("Device Event recevived for {} event {}", event.subject(), event.type());
            if (dhcpServerConnectPoint.get() == null) {
                switch (event.type()) {
                    case DEVICE_ADDED:
                    case DEVICE_AVAILABILITY_CHANGED:
                        // some device is available check if we can get one
                        selectServerConnectPoint();
                        break;
                    default:
                        break;
                }
                return;
            }
            if (dhcpServerConnectPoint.get().deviceId().
                    equals(event.subject().id())) {
                switch (event.type()) {
                    case DEVICE_AVAILABILITY_CHANGED:
                    case DEVICE_REMOVED:
                    case DEVICE_SUSPENDED:
                        // state of our device has changed, check if we need
                        // to re-select
                        selectServerConnectPoint();
                        break;
                    default:
                        break;
                }
            }
        }
    }
}
