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

import static org.onlab.packet.DHCP.DHCPOptionCode.OptionCode_MessageType;
import static org.onlab.packet.MacAddress.valueOf;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Dictionary;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Modified;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onlab.packet.DHCP;
import org.onlab.packet.DHCPPacketType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
import org.onlab.packet.VlanId;
import org.onlab.packet.dhcp.DhcpOption;
import org.onlab.util.Tools;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.event.AbstractListenerManager;
import org.onosproject.mastership.MastershipEvent;
import org.onosproject.mastership.MastershipListener;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.AnnotationKeys;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.opencord.dhcpl2relay.DhcpAllocationInfo;
import org.opencord.dhcpl2relay.DhcpL2RelayEvent;
import org.opencord.dhcpl2relay.DhcpL2RelayListener;
import org.opencord.dhcpl2relay.DhcpL2RelayService;
import org.opencord.dhcpl2relay.impl.packet.DhcpOption82;
import org.opencord.sadis.BaseInformationService;
import org.opencord.sadis.SadisService;
import org.opencord.sadis.SubscriberAndDeviceInformation;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;

/**
 * DHCP Relay Agent Application Component.
 */
@Service
@Component(immediate = true)
public class DhcpL2Relay
        extends AbstractListenerManager<DhcpL2RelayEvent, DhcpL2RelayListener>
        implements DhcpL2RelayService {

    public static final String DHCP_L2RELAY_APP = "org.opencord.dhcpl2relay";
    private static final String HOST_LOC_PROVIDER =
            "org.onosproject.provider.host.impl.HostLocationProvider";
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
    protected SadisService sadisService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected MastershipService mastershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowObjectiveService flowObjectiveService;

    @Property(name = "option82", boolValue = true,
            label = "Add option 82 to relayed packets")
    protected boolean option82 = true;

    @Property(name = "enableDhcpBroadcastReplies", boolValue = false,
            label = "Ask the DHCP Server to send back replies as L2 broadcast")
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
    private boolean modifyClientPktsSrcDstMac = false;
    //Whether to use the uplink port of the OLTs to send/receive messages to the DHCP server
    private boolean useOltUplink = false;

    private BaseInformationService<SubscriberAndDeviceInformation> subsService;

    @Activate
    protected void activate(ComponentContext context) {
        //start the dhcp relay agent
        appId = coreService.registerApplication(DHCP_L2RELAY_APP);
        // ensure that host-learning via dhcp includes IP addresses
        componentConfigService.preSetProperty(HOST_LOC_PROVIDER,
                                              "useDhcp", Boolean.TRUE.toString());
        componentConfigService.registerProperties(getClass());
        eventDispatcher.addSink(DhcpL2RelayEvent.class, listenerRegistry);

        cfgService.addListener(cfgListener);
        mastershipService.addListener(changeListener);
        deviceService.addListener(deviceListener);

        factories.forEach(cfgService::registerConfigFactory);
        //update the dhcp server configuration.
        updateConfig();
        //add the packet services.
        packetService.addProcessor(dhcpRelayPacketProcessor,
                PacketProcessor.director(0));
        if (context != null) {
            modified(context);
        }

        subsService = sadisService.getSubscriberInfoService();

        log.info("DHCP-L2-RELAY Started");
    }

    @Deactivate
    protected void deactivate() {
        cfgService.removeListener(cfgListener);
        factories.forEach(cfgService::unregisterConfigFactory);
        packetService.removeProcessor(dhcpRelayPacketProcessor);
        cancelDhcpPktsFromServer();

        componentConfigService.unregisterProperties(getClass(), false);
        deviceService.removeListener(deviceListener);
        mastershipService.removeListener(changeListener);
        eventDispatcher.removeSink(DhcpL2RelayEvent.class);
        log.info("DHCP-L2-RELAY Stopped");
    }

    @Modified
    protected void modified(ComponentContext context) {

        Dictionary<?, ?> properties = context.getProperties();

        Boolean o = Tools.isPropertyEnabled(properties, "option82");
        if (o != null) {
            option82 = o;
        }

        o = Tools.isPropertyEnabled(properties, "enableDhcpBroadcastReplies");
        if (o != null) {
            enableDhcpBroadcastReplies = o;
        }
    }

    /**
     * Checks if this app has been configured.
     *
     * @return true if all information we need have been initialized
     */
    private boolean configured() {
        if (!useOltUplink) {
            return dhcpServerConnectPoint.get() != null;
        }
        return true;
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
        modifyClientPktsSrcDstMac = cfg.getModifySrcDstMacAddresses();
        boolean prevUseOltUplink = useOltUplink;
        useOltUplink = cfg.getUseOltUplinkForServerPktInOut();

        if (useOltUplink) {
            for (ConnectPoint cp : getUplinkPortsOfOlts()) {
                log.debug("requestDhcpPackets: ConnectPoint: {}", cp);
                requestDhcpPacketsFromConnectPoint(cp, null);
            }
            // check if previous config was different and so trap flows may
            // need to be removed from other places like AGG switches
            if (!prevUseOltUplink) {
                addOrRemoveDhcpTrapFromServer(false);
            }
        } else {
            // uplink on AGG switch
            addOrRemoveDhcpTrapFromServer(true);
        }
    }

    private void cancelDhcpPktsFromServer() {
        if (useOltUplink) {
            for (ConnectPoint cp : getUplinkPortsOfOlts()) {
                log.debug("cancelDhcpPackets: ConnectPoint: {}", cp);
                cancelDhcpPacketsFromConnectPoint(cp, null);
            }
        } else {
            // uplink on AGG switch
            addOrRemoveDhcpTrapFromServer(false);
        }
    }

    /**
     * Used to add or remove DHCP trap flow for packets received from DHCP server.
     * Typically used on a non OLT device, like an AGG switch. When adding, a
     * new dhcp server connect point is selected from the configured options.
     *
     * @param add true if dhcp trap flow is to be added, false to remove the
     *            trap flow
     */
    private void addOrRemoveDhcpTrapFromServer(boolean add) {
        if (add) {
            selectServerConnectPoint();
            log.debug("dhcp server connect point: " + dhcpServerConnectPoint);
        }
        if (dhcpServerConnectPoint.get() == null) {
            log.warn("No dhcpServer connectPoint found, cannot {} dhcp trap flows",
                     (add) ? "install" : "remove");
            return;
        }
        if (add) {
            log.info("Adding trap to dhcp server connect point: "
                    + dhcpServerConnectPoint);
            requestDhcpPacketsFromConnectPoint(dhcpServerConnectPoint.get(),
                                               Optional.of(PacketPriority.HIGH1));
        } else {
            log.info("Removing trap from dhcp server connect point: "
                    + dhcpServerConnectPoint);
            cancelDhcpPacketsFromConnectPoint(dhcpServerConnectPoint.get(),
                                              Optional.of(PacketPriority.HIGH1));
        }
    }

    /**
     * Returns all the uplink ports of OLTs configured in SADIS.
     * Only ports visible in ONOS and for which this instance is master
     * are returned
     */
    private List<ConnectPoint> getUplinkPortsOfOlts() {
        List<ConnectPoint> cps = new ArrayList<>();

        // find all the olt devices and if their uplink ports are visible
        Iterable<Device> devices = deviceService.getDevices();
        for (Device d : devices) {
            // check if this device is provisioned in Sadis

            log.debug("getUplinkPortsOfOlts: Checking mastership of {}", d);
            // do only for devices for which we are the master
            if (!mastershipService.isLocalMaster(d.id())) {
                continue;
            }

            String devSerialNo = d.serialNumber();
            SubscriberAndDeviceInformation deviceInfo = subsService.get(devSerialNo);
            log.debug("getUplinkPortsOfOlts: Found device: {}", deviceInfo);
            if (deviceInfo != null) {
                // check if the uplink port with that number is available on the device
                PortNumber pNum = PortNumber.portNumber(deviceInfo.uplinkPort());
                Port port = deviceService.getPort(d.id(), pNum);
                log.debug("getUplinkPortsOfOlts: Found port: {}", port);
                if (port != null) {
                    cps.add(new ConnectPoint(d.id(), pNum));
                }
            }
        }
        return cps;
    }

    /**
     * Returns whether the passed port is the uplink port of the olt device.
     */
    private boolean isUplinkPortOfOlt(DeviceId dId, Port p) {
        log.debug("isUplinkPortOfOlt: DeviceId: {} Port: {}", dId, p);
        // do only for devices for which we are the master
        if (!mastershipService.isLocalMaster(dId)) {
            return false;
        }

        Device d = deviceService.getDevice(dId);
        SubscriberAndDeviceInformation deviceInfo = subsService.get(d.serialNumber());

        if (deviceInfo != null) {
            return (deviceInfo.uplinkPort() == p.number().toLong());
        }

        return false;
    }

    /**
     * Returns the connectPoint which is the uplink port of the OLT.
     */
    private ConnectPoint getUplinkConnectPointOfOlt(DeviceId dId) {

        Device d = deviceService.getDevice(dId);
        SubscriberAndDeviceInformation deviceInfo = subsService.get(d.serialNumber());
        log.debug("getUplinkConnectPointOfOlt DeviceId: {} devInfo: {}", dId, deviceInfo);
        if (deviceInfo != null) {
            PortNumber pNum = PortNumber.portNumber(deviceInfo.uplinkPort());
            Port port = deviceService.getPort(d.id(), pNum);
            if (port != null) {
                return new ConnectPoint(d.id(), pNum);
            }
        }

        return null;
    }

    /**
     * Request DHCP packet from particular connect point via PacketService.
     * Optionally provide a priority for the trap flow. If no such priority is
     * provided, the default priority will be used.
     *
     * @param cp the connect point to trap dhcp packets from
     * @param priority of the trap flow, null to use default priority
     */
    private void requestDhcpPacketsFromConnectPoint(ConnectPoint cp,
                                                    Optional<PacketPriority> priority) {
        TrafficSelector.Builder selectorServer = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchInPort(cp.port())
                .matchIPProtocol(IPv4.PROTOCOL_UDP)
                .matchUdpSrc(TpPort.tpPort(UDP.DHCP_SERVER_PORT));
        packetService.requestPackets(selectorServer.build(),
                priority.isPresent() ? priority.get() : PacketPriority.CONTROL,
                appId, Optional.of(cp.deviceId()));
    }

    /**
     * Cancel DHCP packet from particular connect point via PacketService. If
     * the request was made with a specific packet priority, then the same
     * priority should be used in this call.
     *
     * @param cp the connect point for the trap flow
     * @param priority with which the trap flow was requested; if request
     *            priority was not specified, this param should also be null
     */
    private void cancelDhcpPacketsFromConnectPoint(ConnectPoint cp,
                                                   Optional<PacketPriority> priority) {
        TrafficSelector.Builder selectorServer = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchInPort(cp.port())
                .matchIPProtocol(IPv4.PROTOCOL_UDP)
                .matchUdpSrc(TpPort.tpPort(UDP.DHCP_SERVER_PORT));
        packetService.cancelPackets(selectorServer.build(),
                priority.isPresent() ? priority.get() : PacketPriority.CONTROL,
                appId, Optional.of(cp.deviceId()));
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
            Ethernet packet = context.inPacket().parsed();

            if (packet == null) {
                log.warn("Packet is null");
                return;
            }

            if (packet.getEtherType() == Ethernet.TYPE_IPV4) {
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
        private void forwardPacket(Ethernet packet, PacketContext context) {
            ConnectPoint toSendTo = null;

            if (!useOltUplink) {
                toSendTo = dhcpServerConnectPoint.get();
            } else {
                toSendTo = getUplinkConnectPointOfOlt(context.inPacket().
                                                      receivedFrom().deviceId());
            }

            if (toSendTo != null) {
                TrafficTreatment t = DefaultTrafficTreatment.builder()
                        .setOutput(toSendTo.port()).build();
                OutboundPacket o = new DefaultOutboundPacket(
                        toSendTo.deviceId(), t,
                        ByteBuffer.wrap(packet.serialize()));
                if (log.isTraceEnabled()) {
                    log.trace("Relaying packet to dhcp server at {} {}",
                              toSendTo, packet);
                }
                packetService.emit(o);
            } else {
                log.error("No connect point to send msg to DHCP Server");
            }
        }

        // get the type of the DHCP packet
        private DHCPPacketType getDhcpPacketType(DHCP dhcpPayload) {

            for (DhcpOption option : dhcpPayload.getOptions()) {
                if (option.getCode() == OptionCode_MessageType.getValue()) {
                    byte[] data = option.getData();
                    return DHCPPacketType.getType(data[0]);
                }
            }
            return null;
        }

        //process the dhcp packet before sending to server
        private void processDhcpPacket(PacketContext context, Ethernet packet,
                                       DHCP dhcpPayload) {
            if (dhcpPayload == null) {
                log.warn("DHCP payload is null");
                return;
            }

            DHCPPacketType incomingPacketType = getDhcpPacketType(dhcpPayload);

            log.info("Received DHCP Packet of type {} from {}",
                     incomingPacketType, context.inPacket().receivedFrom());

            switch (incomingPacketType) {
                case DHCPDISCOVER:
                    Ethernet ethernetPacketDiscover =
                            processDhcpPacketFromClient(context, packet);
                    if (ethernetPacketDiscover != null) {
                        forwardPacket(ethernetPacketDiscover, context);
                    }
                    break;
                case DHCPOFFER:
                    //reply to dhcp client.
                    Ethernet ethernetPacketOffer =
                            processDhcpPacketFromServer(context, packet);
                    if (ethernetPacketOffer != null) {
                        sendReply(ethernetPacketOffer, dhcpPayload);
                    }
                    break;
                case DHCPREQUEST:
                    Ethernet ethernetPacketRequest =
                            processDhcpPacketFromClient(context, packet);
                    if (ethernetPacketRequest != null) {
                        forwardPacket(ethernetPacketRequest, context);
                    }
                    break;
                case DHCPACK:
                    //reply to dhcp client.
                    Ethernet ethernetPacketAck =
                            processDhcpPacketFromServer(context, packet);
                    if (ethernetPacketAck != null) {
                        sendReply(ethernetPacketAck, dhcpPayload);
                    }
                    break;
                default:
                    break;
            }
        }

        private Ethernet processDhcpPacketFromClient(PacketContext context,
                                                     Ethernet ethernetPacket) {
            if (log.isTraceEnabled()) {
                log.trace("DHCP packet received from client at {} {}",
                          context.inPacket().receivedFrom(), ethernetPacket);
            }

            MacAddress relayAgentMac = relayAgentMacAddress(context);
            if (relayAgentMac == null) {
                log.warn("RelayAgent MAC not found ");
                return null;
            }

            Ethernet etherReply = ethernetPacket;

            IPv4 ipv4Packet = (IPv4) etherReply.getPayload();
            UDP udpPacket = (UDP) ipv4Packet.getPayload();
            DHCP dhcpPacket = (DHCP) udpPacket.getPayload();

            if (enableDhcpBroadcastReplies) {
                // We want the reply to come back as a L2 broadcast
                dhcpPacket.setFlags((short) 0x8000);
            }

            MacAddress clientMac = MacAddress.valueOf(dhcpPacket.getClientHardwareAddress());
            IpAddress clientIp = IpAddress.valueOf(dhcpPacket.getClientIPAddress());

            SubscriberAndDeviceInformation entry = getSubscriber(context);
            if (entry == null) {
                log.warn("Dropping packet as subscriber entry is not available");
                return null;
            }

            DhcpAllocationInfo info = new DhcpAllocationInfo(
                    context.inPacket().receivedFrom(), dhcpPacket.getPacketType(),
                    entry.nasPortId(), clientMac, clientIp);

            allocationMap.put(entry.nasPortId(), info);

            post(new DhcpL2RelayEvent(DhcpL2RelayEvent.Type.UPDATED, info,
                                      context.inPacket().receivedFrom()));

            if (option82) {
                DHCP dhcpPacketWithOption82 = addOption82(dhcpPacket, entry);
                udpPacket.setPayload(dhcpPacketWithOption82);
            }

            ipv4Packet.setPayload(udpPacket);
            etherReply.setPayload(ipv4Packet);
            if (modifyClientPktsSrcDstMac) {
                etherReply.setSourceMACAddress(relayAgentMac);
                etherReply.setDestinationMACAddress(dhcpConnectMac);
            }

            etherReply.setPriorityCode(ethernetPacket.getPriorityCode());
            etherReply.setVlanID(cTag(context).toShort());
            etherReply.setQinQTPID(Ethernet.TYPE_VLAN);
            etherReply.setQinQVID(sTag(context).toShort());
            log.info("Finished processing packet.. relaying to dhcpServer");
            return etherReply;
        }

        //build the DHCP offer/ack with proper client port.
        private Ethernet processDhcpPacketFromServer(PacketContext context,
                                                     Ethernet ethernetPacket) {
            if (log.isTraceEnabled()) {
                log.trace("DHCP packet received from server at {} {}",
                          context.inPacket().receivedFrom(), ethernetPacket);
            }
            // get dhcp header.
            Ethernet etherReply = (Ethernet) ethernetPacket.clone();
            IPv4 ipv4Packet = (IPv4) etherReply.getPayload();
            UDP udpPacket = (UDP) ipv4Packet.getPayload();
            DHCP dhcpPayload = (DHCP) udpPacket.getPayload();

            MacAddress dstMac = valueOf(dhcpPayload.getClientHardwareAddress());
            ConnectPoint subsCp = getConnectPointOfClient(dstMac);
            // If we can't find the subscriber, can't process further
            if (subsCp == null) {
                return null;
            }
            // if it's an ACK packet store the information for display purpose
            if (getDhcpPacketType(dhcpPayload) == DHCPPacketType.DHCPACK) {

                String portId = nasPortId(subsCp);
                SubscriberAndDeviceInformation sub = subsService.get(portId);
                if (sub != null) {
                    List<DhcpOption> options = dhcpPayload.getOptions();
                    List<DhcpOption> circuitIds = options.stream()
                            .filter(option -> option.getCode() == DHCP.DHCPOptionCode.OptionCode_CircuitID.getValue())
                            .collect(Collectors.toList());

                    String circuitId = "None";
                    if (circuitIds.size() == 1) {
                        byte[] array = circuitIds.get(0).getData();

                        try {
                            // we leave the first two bytes as they are the id and length
                            circuitId = new String(Arrays.copyOfRange(array, 2, array.length), "UTF-8");
                        } catch (Exception e) { }
                    }

                    IpAddress ip = IpAddress.valueOf(dhcpPayload.getYourIPAddress());

                    //storeDHCPAllocationInfo
                    DhcpAllocationInfo info = new DhcpAllocationInfo(subsCp,
                            dhcpPayload.getPacketType(), circuitId, dstMac, ip);

                    allocationMap.put(sub.nasPortId(), info);

                    post(new DhcpL2RelayEvent(DhcpL2RelayEvent.Type.UPDATED, info, subsCp));
                }
            } // end storing of info

            // we leave the srcMac from the original packet
            etherReply.setDestinationMACAddress(dstMac);
            etherReply.setQinQVID(sTag(subsCp).toShort());
            etherReply.setPriorityCode(ethernetPacket.getPriorityCode());
            etherReply.setVlanID((cTag(subsCp).toShort()));

            if (option82) {
                udpPacket.setPayload(removeOption82(dhcpPayload));
            } else {
                udpPacket.setPayload(dhcpPayload);
            }
            ipv4Packet.setPayload(udpPacket);
            etherReply.setPayload(ipv4Packet);

            log.info("Finished processing packet.. relaying to client");
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
        private void sendReply(Ethernet ethPacket, DHCP dhcpPayload) {
            MacAddress descMac = valueOf(dhcpPayload.getClientHardwareAddress());
            ConnectPoint subCp = getConnectPointOfClient(descMac);

            // Send packet out to requester if the host information is available
            if (subCp != null) {
                log.info("Sending DHCP packet to client at {}", subCp);
                TrafficTreatment t = DefaultTrafficTreatment.builder()
                        .setOutput(subCp.port()).build();
                OutboundPacket o = new DefaultOutboundPacket(
                        subCp.deviceId(), t, ByteBuffer.wrap(ethPacket.serialize()));
                if (log.isTraceEnabled()) {
                    log.trace("Relaying packet to dhcp client at {} {}", subCp,
                              ethPacket);
                }
                packetService.emit(o);
            } else {
                log.error("Dropping DHCP packet because can't find host for {}", descMac);
            }
        }
    }

    private DHCP addOption82(DHCP dhcpPacket, SubscriberAndDeviceInformation entry) {
        log.debug("option82data {} ", entry);

        List<DhcpOption> options = Lists.newArrayList(dhcpPacket.getOptions());
        DhcpOption82 option82 = new DhcpOption82();
        option82.setAgentCircuitId(entry.circuitId());
        option82.setAgentRemoteId(entry.remoteId());
        DhcpOption option = new DhcpOption()
                .setCode(DHCP.DHCPOptionCode.OptionCode_CircuitID.getValue())
                .setData(option82.toByteArray())
                .setLength(option82.length());

        options.add(options.size() - 1, option);
        dhcpPacket.setOptions(options);

        return dhcpPacket;

    }

    private DHCP removeOption82(DHCP dhcpPacket) {
        List<DhcpOption> options = dhcpPacket.getOptions();
        List<DhcpOption> newoptions = options.stream()
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
            if (!useOltUplink) {
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
    }

    /**
     * Handles Device status change for the devices which connect
     * to the DHCP server.
     */
    private class InnerDeviceListener implements DeviceListener {
        @Override
        public void event(DeviceEvent event) {
            if (log.isTraceEnabled() &&
                    !event.type().equals(DeviceEvent.Type.PORT_STATS_UPDATED)) {
                log.trace("Device Event received for {} event {}",
                          event.subject(), event.type());
            }
            if (!useOltUplink) {
                if (dhcpServerConnectPoint.get() == null) {
                    switch (event.type()) {
                        case DEVICE_ADDED:
                        case DEVICE_AVAILABILITY_CHANGED:
                            // some device is available check if we can get a
                            // connect point we can use
                            addOrRemoveDhcpTrapFromServer(true);
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
                            // to re-select a connectpoint
                            addOrRemoveDhcpTrapFromServer(true);
                            break;
                        default:
                            break;
                    }
                }
            } else {
                switch (event.type()) {
                    case PORT_ADDED:
                        if (useOltUplink && isUplinkPortOfOlt(event.subject().id(), event.port())) {
                            requestDhcpPacketsFromConnectPoint(
                                new ConnectPoint(event.subject().id(), event.port().number()),
                                null);
                        }
                        break;
                    default:
                        break;
                }
            }
        }
    }
}
