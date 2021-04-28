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

import static java.util.concurrent.Executors.newFixedThreadPool;
import static java.util.concurrent.Executors.newSingleThreadExecutor;
import static org.onlab.packet.DHCP.DHCPOptionCode.OptionCode_MessageType;
import static org.onlab.packet.MacAddress.valueOf;
import static org.onlab.util.Tools.groupedThreads;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;
import static org.opencord.dhcpl2relay.impl.OsgiPropertyConstants.ENABLE_DHCP_BROADCAST_REPLIES;
import static org.opencord.dhcpl2relay.impl.OsgiPropertyConstants.ENABLE_DHCP_BROADCAST_REPLIES_DEFAULT;
import static org.opencord.dhcpl2relay.impl.OsgiPropertyConstants.OPTION_82;
import static org.opencord.dhcpl2relay.impl.OsgiPropertyConstants.OPTION_82_DEFAULT;
import static org.opencord.dhcpl2relay.impl.OsgiPropertyConstants.PACKET_PROCESSOR_THREADS;
import static org.opencord.dhcpl2relay.impl.OsgiPropertyConstants.PACKET_PROCESSOR_THREADS_DEFAULT;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Dictionary;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.apache.commons.io.HexDump;
import org.onlab.packet.DHCP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
import org.onlab.packet.VlanId;
import org.onlab.packet.dhcp.DhcpOption;
import org.onlab.packet.dhcp.DhcpRelayAgentOption;
import org.onlab.util.KryoNamespace;
import org.onlab.util.Tools;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.cluster.ClusterService;
import org.onosproject.cluster.LeadershipService;
import org.onosproject.cluster.NodeId;
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
import org.onosproject.store.serializers.KryoNamespaces;
import org.onosproject.store.service.ConsistentMap;
import org.onosproject.store.service.Serializer;
import org.onosproject.store.service.StorageService;
import org.onosproject.store.service.Versioned;
import org.opencord.dhcpl2relay.DhcpAllocationInfo;
import org.opencord.dhcpl2relay.DhcpL2RelayEvent;
import org.opencord.dhcpl2relay.DhcpL2RelayListener;
import org.opencord.dhcpl2relay.DhcpL2RelayService;
import org.opencord.dhcpl2relay.DhcpL2RelayStoreDelegate;
import org.opencord.dhcpl2relay.impl.packet.DhcpOption82Data;
import org.opencord.sadis.BaseInformationService;
import org.opencord.sadis.SadisService;
import org.opencord.sadis.SubscriberAndDeviceInformation;
import org.opencord.sadis.UniTagInformation;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

/**
 * DHCP Relay Agent Application Component.
 */
@Component(immediate = true,
        property = {
                OPTION_82 + ":Boolean=" + OPTION_82_DEFAULT,
                ENABLE_DHCP_BROADCAST_REPLIES + ":Boolean=" + ENABLE_DHCP_BROADCAST_REPLIES_DEFAULT,
                PACKET_PROCESSOR_THREADS + ":Integer=" + PACKET_PROCESSOR_THREADS_DEFAULT,
        })
public class DhcpL2Relay
        extends AbstractListenerManager<DhcpL2RelayEvent, DhcpL2RelayListener>
        implements DhcpL2RelayService {
    private static final String SADIS_NOT_RUNNING = "Sadis is not running.";
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

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService componentConfigService;

    @Reference(cardinality = ReferenceCardinality.OPTIONAL,
            bind = "bindSadisService",
            unbind = "unbindSadisService",
            policy = ReferencePolicy.DYNAMIC)
    protected volatile SadisService sadisService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected MastershipService mastershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected StorageService storageService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DhcpL2RelayCountersStore dhcpL2RelayCounters;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected LeadershipService leadershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ClusterService clusterService;

    // OSGi Properties
    /**
     * Add option 82 to relayed packets.
     */
    protected boolean option82 = OPTION_82_DEFAULT;
    /**
     * Ask the DHCP Server to send back replies as L2 broadcast.
     */
    protected boolean enableDhcpBroadcastReplies = ENABLE_DHCP_BROADCAST_REPLIES_DEFAULT;

    /**
     * Number of threads used to process the packet.
     */
    protected int packetProcessorThreads = PACKET_PROCESSOR_THREADS_DEFAULT;

    ScheduledFuture<?> refreshTask;
    ScheduledExecutorService refreshService = Executors.newSingleThreadScheduledExecutor();

    private DhcpRelayPacketProcessor dhcpRelayPacketProcessor =
            new DhcpRelayPacketProcessor();

    private InnerMastershipListener changeListener = new InnerMastershipListener();
    private InnerDeviceListener deviceListener = new InnerDeviceListener();

    // connect points to the DHCP server
    Set<ConnectPoint> dhcpConnectPoints;
    protected AtomicReference<ConnectPoint> dhcpServerConnectPoint = new AtomicReference<>();
    private MacAddress dhcpConnectMac = MacAddress.BROADCAST;
    private ApplicationId appId;

    private ConsistentMap<String, DhcpAllocationInfo> allocations;
    protected boolean modifyClientPktsSrcDstMac = false;
    //Whether to use the uplink port of the OLTs to send/receive messages to the DHCP server
    protected boolean useOltUplink = false;

    private BaseInformationService<SubscriberAndDeviceInformation> subsService;

    private DhcpL2RelayStoreDelegate delegate = new InnerDhcpL2RelayStoreDelegate();

    protected ExecutorService packetProcessorExecutor;
    protected ExecutorService eventHandlerExecutor;

    @Activate
    protected void activate(ComponentContext context) {

        //start the dhcp relay agent
        appId = coreService.registerApplication(DHCP_L2RELAY_APP);
        componentConfigService.registerProperties(getClass());
        eventDispatcher.addSink(DhcpL2RelayEvent.class, listenerRegistry);

        KryoNamespace serializer = KryoNamespace.newBuilder()
                .register(KryoNamespaces.API)
                .register(Instant.class)
                .register(DHCP.MsgType.class)
                .register(DhcpAllocationInfo.class)
                .build();

        allocations = storageService.<String, DhcpAllocationInfo>consistentMapBuilder()
                .withName("dhcpl2relay-allocations")
                .withSerializer(Serializer.using(serializer))
                .withApplicationId(appId)
                .build();

        dhcpL2RelayCounters.setDelegate(delegate);

        eventHandlerExecutor = newSingleThreadExecutor(groupedThreads("onos/dhcp", "dhcp-event-%d", log));

        cfgService.addListener(cfgListener);
        mastershipService.addListener(changeListener);
        deviceService.addListener(deviceListener);

        if (sadisService != null) {
            subsService = sadisService.getSubscriberInfoService();
        } else {
            log.warn(SADIS_NOT_RUNNING);
        }
        factories.forEach(cfgService::registerConfigFactory);
        //update the dhcp server configuration.
        updateConfig();

        if (context != null) {
            modified(context);
        }

        //add the packet services.
        packetService.addProcessor(dhcpRelayPacketProcessor,
                                   PacketProcessor.director(0));

        log.info("DHCP-L2-RELAY Started");
    }

    @Deactivate
    protected void deactivate() {
        if (refreshTask != null) {
            refreshTask.cancel(true);
        }
        if (refreshService != null) {
            refreshService.shutdownNow();
        }
        dhcpL2RelayCounters.unsetDelegate(delegate);
        cfgService.removeListener(cfgListener);
        factories.forEach(cfgService::unregisterConfigFactory);
        packetService.removeProcessor(dhcpRelayPacketProcessor);
        cancelDhcpPktsFromServer();

        packetProcessorExecutor.shutdown();
        eventHandlerExecutor.shutdown();
        componentConfigService.unregisterProperties(getClass(), false);
        deviceService.removeListener(deviceListener);
        mastershipService.removeListener(changeListener);
        eventDispatcher.removeSink(DhcpL2RelayEvent.class);
        log.info("DHCP-L2-RELAY Stopped");
    }

    @Modified
    protected void modified(ComponentContext context) {

        Dictionary<?, ?> properties = context.getProperties();

        Boolean o = Tools.isPropertyEnabled(properties, OPTION_82);
        if (o != null) {
            option82 = o;
        }

        o = Tools.isPropertyEnabled(properties, ENABLE_DHCP_BROADCAST_REPLIES);
        if (o != null) {
            enableDhcpBroadcastReplies = o;
        }

        String s = Tools.get(properties, PACKET_PROCESSOR_THREADS);
        int oldpacketProcessorThreads = packetProcessorThreads;
        packetProcessorThreads = Strings.isNullOrEmpty(s) ? oldpacketProcessorThreads
                : Integer.parseInt(s.trim());
        if (packetProcessorExecutor == null || oldpacketProcessorThreads != packetProcessorThreads) {
            if (packetProcessorExecutor != null) {
                packetProcessorExecutor.shutdown();
            }
            packetProcessorExecutor = newFixedThreadPool(packetProcessorThreads,
                    groupedThreads("onos/dhcp",
                            "dhcp-packet-%d", log));
        }
    }

    protected void bindSadisService(SadisService service) {
        sadisService = service;
        subsService = sadisService.getSubscriberInfoService();
        log.info("Sadis-service binds to onos.");
    }

    protected void unbindSadisService(SadisService service) {
        sadisService = null;
        subsService = null;
        log.info("Sadis-service unbinds from onos.");
    }

    @Override
    public Map<String, DhcpAllocationInfo> getAllocationInfo() {
        return ImmutableMap.copyOf(allocations.asJavaMap());
    }

    /**
     * Generates a unique UUID from a string.
     *
     * @return true if all information we need have been initialized
     */
    private static String getUniqueUuidFromString(String value) {
        return UUID.nameUUIDFromBytes(value.getBytes()).toString();
    }

    /**
     * Checks if this app has been configured.
     *
     * @return true if all information we need have been initialized
     */
    protected boolean configured() {
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
                for (ConnectPoint cp : dhcpConnectPoints) {
                    if (isLocalLeader(cp.deviceId())) {
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
                requestDhcpPacketsFromConnectPoint(cp, Optional.ofNullable(null));
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
                cancelDhcpPacketsFromConnectPoint(cp, Optional.ofNullable(null));
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
        if (subsService == null) {
            log.warn(SADIS_NOT_RUNNING);
            return Lists.newArrayList();
        }
        List<ConnectPoint> cps = new ArrayList<>();

        // find all the olt devices and if their uplink ports are visible
        Iterable<Device> devices = deviceService.getDevices();
        for (Device d : devices) {
            // check if this device is provisioned in Sadis

            log.debug("getUplinkPortsOfOlts: Checking mastership of {}", d);
            // do only for devices for which we are the master
            if (!isLocalLeader(d.id())) {
                continue;
            }

            String devSerialNo = d.serialNumber();
            SubscriberAndDeviceInformation deviceInfo = getSubscriberAndDeviceInfo(devSerialNo);
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

    private SubscriberAndDeviceInformation getSubscriberAndDeviceInfo(String portOrDevice) {
        if (subsService == null) {
            log.warn(SADIS_NOT_RUNNING);
            return null;
        }
        return subsService.get(portOrDevice);
    }

    /**
     * Returns whether the passed port is the uplink port of the olt device.
     */
    private boolean isUplinkPortOfOlt(DeviceId dId, Port p) {
        log.debug("isUplinkPortOfOlt: DeviceId: {} Port: {}", dId, p);

        Device d = deviceService.getDevice(dId);
        SubscriberAndDeviceInformation deviceInfo = getSubscriberAndDeviceInfo(d.serialNumber());

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
        SubscriberAndDeviceInformation deviceInfo = getSubscriberAndDeviceInfo(d.serialNumber());
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
     * @param cp       the connect point to trap dhcp packets from
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
     * @param cp       the connect point for the trap flow
     * @param priority with which the trap flow was requested; if request
     *                 priority was not specified, this param should also be null
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

    /**
     * Main packet-processing engine for dhcp l2 relay agent.
     */
    private class DhcpRelayPacketProcessor implements PacketProcessor {
        private static final String VLAN_KEYWORD = ":vlan";
        private static final String PCP_KEYWORD = ":pcp";

        @Override
        public void process(PacketContext context) {
            packetProcessorExecutor.execute(() -> {
                processInternal(context);
            });
        }

        private void processInternal(PacketContext context) {
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
                        if (log.isTraceEnabled()) {
                            log.trace("Processing packet with type {} from MAC {}",
                                      getDhcpPacketType(dhcpPayload),
                                      MacAddress.valueOf(dhcpPayload.getClientHardwareAddress()));
                        }
                        //This packet is dhcp.
                        processDhcpPacket(context, packet, dhcpPayload);
                    }
                }
            }
        }

        // process the dhcp packet before relaying to server or client
        private void processDhcpPacket(PacketContext context, Ethernet packet,
                                       DHCP dhcpPayload) {
            if (dhcpPayload == null) {
                log.warn("DHCP payload is null");
                return;
            }

            DHCP.MsgType incomingPacketType = getDhcpPacketType(dhcpPayload);
            if (incomingPacketType == null) {
                log.warn("DHCP Packet type not found. Dump of ethernet pkt in hex format for troubleshooting.");
                byte[] array = packet.serialize();
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                try {
                    HexDump.dump(array, 0, buf, 0);
                    log.trace(buf.toString());
                } catch (Exception e) {
                }
                return;
            }

            SubscriberAndDeviceInformation entry = null;

            MacAddress clientMacAddress = MacAddress.valueOf(dhcpPayload.getClientHardwareAddress());

            log.debug("Received DHCP Packet of type {} from {} with Client MacAddress {} and vlan {}",
                     incomingPacketType, context.inPacket().receivedFrom(),
                     clientMacAddress, packet.getVlanID());

            switch (incomingPacketType) {
                case DHCPDISCOVER:
                    Ethernet ethernetPacketDiscover =
                            processDhcpPacketFromClient(context, packet);
                    if (ethernetPacketDiscover != null) {
                        relayPacketToServer(ethernetPacketDiscover, context);
                    }
                    entry = getSubscriber(context);
                    updateDhcpRelayCountersStore(entry, DhcpL2RelayCounterNames.valueOf("DHCPDISCOVER"));
                    break;
                case DHCPOFFER:
                    RelayToClientInfo r2cDataOffer =
                            processDhcpPacketFromServer(context, packet);
                    if (r2cDataOffer != null) {
                        relayPacketToClient(r2cDataOffer, clientMacAddress);
                        entry = getSubscriber(r2cDataOffer.cp);
                    }
                    updateDhcpRelayCountersStore(entry, DhcpL2RelayCounterNames.valueOf("DHCPOFFER"));
                    break;
                case DHCPREQUEST:
                    Ethernet ethernetPacketRequest =
                            processDhcpPacketFromClient(context, packet);
                    if (ethernetPacketRequest != null) {
                        relayPacketToServer(ethernetPacketRequest, context);
                    }
                    entry = getSubscriber(context);
                    updateDhcpRelayCountersStore(entry, DhcpL2RelayCounterNames.valueOf("DHCPREQUEST"));
                    break;
                case DHCPACK:
                    RelayToClientInfo r2cDataAck =
                            processDhcpPacketFromServer(context, packet);
                    if (r2cDataAck != null) {
                        relayPacketToClient(r2cDataAck, clientMacAddress);
                        entry = getSubscriber(r2cDataAck.cp);
                    }
                    updateDhcpRelayCountersStore(entry, DhcpL2RelayCounterNames.valueOf("DHCPACK"));
                    break;
                case DHCPDECLINE:
                    Ethernet ethernetPacketDecline =
                            processDhcpPacketFromClient(context, packet);
                    if (ethernetPacketDecline != null) {
                        relayPacketToServer(ethernetPacketDecline, context);
                    }
                    entry = getSubscriber(context);
                    updateDhcpRelayCountersStore(entry, DhcpL2RelayCounterNames.valueOf("DHCPDECLINE"));
                    break;
                case DHCPNAK:
                    RelayToClientInfo r2cDataNack =
                            processDhcpPacketFromServer(context, packet);
                    if (r2cDataNack != null) {
                        relayPacketToClient(r2cDataNack, clientMacAddress);
                        entry = getSubscriber(r2cDataNack.cp);
                    }
                    updateDhcpRelayCountersStore(entry, DhcpL2RelayCounterNames.valueOf("DHCPNACK"));
                    break;
                case DHCPRELEASE:
                    Ethernet ethernetPacketRelease =
                            processDhcpPacketFromClient(context, packet);
                    if (ethernetPacketRelease != null) {
                        relayPacketToServer(ethernetPacketRelease, context);
                    }
                    entry = getSubscriber(context);
                    updateDhcpRelayCountersStore(entry, DhcpL2RelayCounterNames.valueOf("DHCPRELEASE"));
                    break;
                default:
                    break;
            }
        }

        /**
         * Processes dhcp packets from clients.
         *
         * @param context the packet context
         * @param ethernetPacket the dhcp packet from client
         * @return the packet to relay to the server
         */
        private Ethernet processDhcpPacketFromClient(PacketContext context,
                                                     Ethernet ethernetPacket) {
            if (log.isTraceEnabled()) {
                log.trace("DHCP Packet received from client at {} {}",
                          context.inPacket().receivedFrom(), ethernetPacket);
            }

            MacAddress relayAgentMac = relayAgentMacAddress(context);
            if (relayAgentMac == null) {
                log.warn("RelayAgent MAC not found ");
                return null;
            }

            Ethernet etherReply = (Ethernet) ethernetPacket.clone();

            IPv4 ipv4Packet = (IPv4) etherReply.getPayload();
            UDP udpPacket = (UDP) ipv4Packet.getPayload();
            DHCP dhcpPacket = (DHCP) udpPacket.getPayload();
            ConnectPoint inPort = context.inPacket().receivedFrom();

            if (enableDhcpBroadcastReplies) {
                // We want the reply to come back as a L2 broadcast
                dhcpPacket.setFlags((short) 0x8000);
            }

            MacAddress clientMac = MacAddress.valueOf(dhcpPacket.getClientHardwareAddress());
            VlanId clientVlan = VlanId.vlanId(ethernetPacket.getVlanID());
            IpAddress clientIp = IpAddress.valueOf(dhcpPacket.getClientIPAddress());

            SubscriberAndDeviceInformation entry = getSubscriber(context);
            if (entry == null) {
                log.warn("Dropping packet as subscriber entry is not available");
                return null;
            }

            UniTagInformation uniTagInformation = getUnitagInformationFromPacketContext(context, entry);
            if (uniTagInformation == null) {
                log.warn("Missing service information for connectPoint {} / cTag {}",
                         inPort, clientVlan);
                return null;
            }
            DhcpOption82Data d82 = null;
            if (option82) {
                DHCP dhcpPacketWithOption82 = addOption82(dhcpPacket, entry,
                                                          inPort, clientVlan,
                                                          uniTagInformation
                                                                  .getDsPonCTagPriority());
                byte[] d82b = dhcpPacketWithOption82
                        .getOption(DHCP.DHCPOptionCode.OptionCode_CircuitID)
                        .getData();
                d82 = new DhcpOption82Data(d82b);
                udpPacket.setPayload(dhcpPacketWithOption82);
            }

            ipv4Packet.setPayload(udpPacket);
            etherReply.setPayload(ipv4Packet);
            if (modifyClientPktsSrcDstMac) {
                etherReply.setSourceMACAddress(relayAgentMac);
                etherReply.setDestinationMACAddress(dhcpConnectMac);
            }

            etherReply.setPriorityCode(ethernetPacket.getPriorityCode());
            etherReply.setVlanID(uniTagInformation.getPonCTag().toShort());
            etherReply.setQinQTPID(Ethernet.TYPE_VLAN);
            etherReply.setQinQVID(uniTagInformation.getPonSTag().toShort());
            if (uniTagInformation.getUsPonSTagPriority() != -1) {
                etherReply.setQinQPriorityCode((byte) uniTagInformation.getUsPonSTagPriority());
            }
            if (uniTagInformation.getUsPonCTagPriority() != -1) {
                etherReply.setPriorityCode((byte) uniTagInformation
                        .getUsPonCTagPriority());
            }

            DhcpAllocationInfo info = new DhcpAllocationInfo(inPort,
                                                             dhcpPacket.getPacketType(),
                                                             (d82 == null)
                                                                 ? entry.circuitId()
                                                                 : d82.getAgentCircuitId(),
                                                             clientMac, clientIp,
                                                             clientVlan, entry.id());
            String key = getUniqueUuidFromString(entry.id() + clientMac
                    + clientVlan);
            allocations.put(key, info);
            post(new DhcpL2RelayEvent(DhcpL2RelayEvent.Type.UPDATED, info, inPort));
            if (log.isTraceEnabled()) {
                log.trace("Finished processing DHCP Packet of type {} with MAC {} from {} "
                        + "... relaying to dhcpServer",
                          dhcpPacket.getPacketType(), clientMac, entry.id());
            }
            return etherReply;
        }

        /**
         * Processes dhcp packets from the server.
         *
         * @param context the packet context
         * @param ethernetPacket the dhcp packet
         * @return returns information necessary for relaying packet to client
         */
        private RelayToClientInfo processDhcpPacketFromServer(PacketContext context,
                                                              Ethernet ethernetPacket) {
            if (log.isTraceEnabled()) {
                log.trace("DHCP Packet received from server at {} {}",
                          context.inPacket().receivedFrom(), ethernetPacket);
            }
            // get dhcp header.
            Ethernet etherReply = (Ethernet) ethernetPacket.clone();
            IPv4 ipv4Packet = (IPv4) etherReply.getPayload();
            UDP udpPacket = (UDP) ipv4Packet.getPayload();
            DHCP dhcpPacket = (DHCP) udpPacket.getPayload();
            VlanId innerVlan = VlanId.vlanId(ethernetPacket.getVlanID());
            MacAddress dstMac = valueOf(dhcpPacket.getClientHardwareAddress());

            // we leave the srcMac from the original packet.
            // TODO remove S-VLAN
            etherReply.setQinQVID(VlanId.NO_VID);
            etherReply.setQinQPriorityCode((byte) 0);
            etherReply.setDestinationMACAddress(dstMac);

            // TODO deserialization of dhcp option82 leaves 'data' field null
            // As a result we need to retrieve suboption data
            RelayToClientInfo r2cData = null;
            boolean usedOption82 = false;
            if (option82) {
                // retrieve connectPoint and vlan from option82, if it is in expected format
                DhcpOption opt = dhcpPacket
                        .getOption(DHCP.DHCPOptionCode.OptionCode_CircuitID);
                if (opt != null && opt instanceof DhcpRelayAgentOption) {
                    DhcpRelayAgentOption d82 = (DhcpRelayAgentOption) opt;
                    DhcpOption d82ckt = d82.getSubOption(DhcpOption82Data.CIRCUIT_ID_CODE);
                    if (d82ckt.getData() != null) {
                        r2cData = decodeCircuitId(new String(d82ckt.getData()));
                    }
                }
                if (r2cData != null) {
                    usedOption82 = true;
                    etherReply.setVlanID(r2cData.cvid.toShort());
                    if (r2cData.pcp != -1) {
                        etherReply.setPriorityCode((byte) r2cData.pcp);
                    }
                }
            }
            // always remove option82 if present
            DHCP remDhcpPacket = removeOption82(dhcpPacket);
            udpPacket.setPayload(remDhcpPacket);

            ipv4Packet.setPayload(udpPacket);
            etherReply.setPayload(ipv4Packet);

            if (!usedOption82) {
                // option 82 data not present or not used, we need to
                // lookup host store with client dstmac and vlan from context
                r2cData = new RelayToClientInfo();
                r2cData.cp = getConnectPointOfClient(dstMac, context);
                if (r2cData.cp == null) {
                    log.warn("Couldn't find subscriber, service or host info for mac"
                            + " address {} and vlan {} .. DHCP packet can't be"
                            + " delivered to client", dstMac, innerVlan);
                    return null;
                }
            }

            // always need the subscriber entry
            SubscriberAndDeviceInformation entry = getSubscriber(r2cData.cp);
            if (entry == null) {
                log.warn("Couldn't find subscriber info for cp {}.. DHCP packet"
                        + " can't be delivered to client mac {} and vlan {}",
                         r2cData.cp, dstMac, innerVlan);
                return null;
            }

            if (!usedOption82) {
                UniTagInformation uniTagInformation =
                        getUnitagInformationFromPacketContext(context, entry);
                if (uniTagInformation == null) {
                    log.warn("Missing service information for connectPoint {} "
                            + " cTag {} .. DHCP packet can't be delivered to client",
                             r2cData.cp, innerVlan);
                    return null;
                }
                r2cData.cvid = uniTagInformation.getPonCTag();
                r2cData.pcp = uniTagInformation.getDsPonCTagPriority();
                r2cData.cktId = entry.circuitId();
                etherReply.setVlanID(r2cData.cvid.toShort());
                if (r2cData.pcp != -1) {
                    etherReply.setPriorityCode((byte) r2cData.pcp);
                }
            }

            // update stats and events
            IpAddress ip = IpAddress.valueOf(dhcpPacket.getYourIPAddress());
            DhcpAllocationInfo info =
                    new DhcpAllocationInfo(r2cData.cp, dhcpPacket.getPacketType(),
                                           r2cData.cktId, dstMac, ip, innerVlan,
                                           entry.id());
            String key = getUniqueUuidFromString(entry.id() + info.macAddress()
                    + innerVlan);
            allocations.put(key, info);
            post(new DhcpL2RelayEvent(DhcpL2RelayEvent.Type.UPDATED, info,
                                      r2cData.cp));
            updateDhcpRelayCountersStore(entry, DhcpL2RelayCounterNames
                    .valueOf("PACKETS_FROM_SERVER"));
            if (log.isTraceEnabled()) {
                log.trace("Finished processing packet.. relaying to client at {}",
                     r2cData.cp);
            }
            r2cData.ethernetPkt = etherReply;
            return r2cData;
        }

        // forward the packet to ConnectPoint where the DHCP server is attached.
        private void relayPacketToServer(Ethernet packet, PacketContext context) {
            SubscriberAndDeviceInformation entry = getSubscriber(context);
            if (log.isTraceEnabled()) {
                IPv4 ipv4Packet = (IPv4) packet.getPayload();
                UDP udpPacket = (UDP) ipv4Packet.getPayload();
                DHCP dhcpPayload = (DHCP) udpPacket.getPayload();
                log.trace("Emitting packet to server: packet {}, with MAC {} from {}",
                          getDhcpPacketType(dhcpPayload),
                          MacAddress.valueOf(dhcpPayload.getClientHardwareAddress()),
                          entry.id());
            }
            ConnectPoint toSendTo = null;
            if (!useOltUplink) {
                toSendTo = dhcpServerConnectPoint.get();
            } else {
                toSendTo = getUplinkConnectPointOfOlt(context.inPacket().receivedFrom()
                        .deviceId());
            }

            if (toSendTo != null) {
                TrafficTreatment t = DefaultTrafficTreatment.builder()
                        .setOutput(toSendTo.port()).build();
                OutboundPacket o = new DefaultOutboundPacket(toSendTo
                        .deviceId(), t, ByteBuffer.wrap(packet.serialize()));
                if (log.isTraceEnabled()) {
                    log.trace("Relaying packet to dhcp server at {} {}", toSendTo,
                              packet);
                }
                packetService.emit(o);

                updateDhcpRelayCountersStore(entry, DhcpL2RelayCounterNames
                        .valueOf("PACKETS_TO_SERVER"));
            } else {
                log.error("No connect point to send msg to DHCP Server");
            }
        }

        // send the response to the requester host (client)
        private void relayPacketToClient(RelayToClientInfo r2cData,
                                         MacAddress dstMac) {
            ConnectPoint subCp = r2cData.cp;
            Ethernet ethPacket = r2cData.ethernetPkt;
            // Send packet out to requester if the host information is available
            if (subCp != null) {
                TrafficTreatment t = DefaultTrafficTreatment.builder()
                        .setOutput(subCp.port()).build();
                OutboundPacket o = new DefaultOutboundPacket(subCp.deviceId(),
                                        t, ByteBuffer.wrap(ethPacket.serialize()));
                if (log.isTraceEnabled()) {
                    log.trace("Relaying packet to DHCP client at {} with "
                        + "MacAddress {}, {} given {}", subCp, dstMac,
                         ethPacket, r2cData);
                }
                packetService.emit(o);
            } else {
                log.error("Dropping DHCP Packet because unknown connectPoint for {}",
                          dstMac);
            }
        }

        /**
         * Option 82 includes circuitId and remoteId data configured by an
         * operator in sadis for a subscriber, and can be a string in any form
         * relevant to the operator's dhcp-server. When circuitId is configured
         * in sadis, the relay agent adds the option, but does not use the
         * information for forwarding packets back to client.
         * <p>
         * If circuitId is not configured in sadis, this relay-agent adds
         * circuitId information in the form
         * "{@literal<}connectPoint>:vlan{@literal<}clientVlanId>:pcp{@literal<}downstreamPcp>"
         * for example, "of:0000000000000001/32:vlan200:pcp7". When the packet
         * is received back from the server with circuitId in this form, this
         * relay agent will use this information to forward packets to the
         * client.
         *
         * @param dhcpPacket the DHCP packet to transform
         * @param entry sadis information for the subscriber
         * @param cp the connectPoint to set if sadis entry has no circuitId
         * @param clientVlan the vlan to set if sadis entry has no circuitId
         * @param downstreamPbits the pbits to set if sadis entry has no
         *            circuitId
         * @return the modified dhcp packet with option82 added
         */
        private DHCP addOption82(DHCP dhcpPacket, SubscriberAndDeviceInformation entry,
                                 ConnectPoint cp, VlanId clientVlan,
                                 int downstreamPbits) {
            List<DhcpOption> options = Lists.newArrayList(dhcpPacket.getOptions());
            DhcpOption82Data option82 = new DhcpOption82Data();
            if (entry.circuitId() == null || entry.circuitId().isBlank()) {
                option82.setAgentCircuitId(cp + VLAN_KEYWORD + clientVlan
                        + PCP_KEYWORD
                        + downstreamPbits);
            } else {
                option82.setAgentCircuitId(entry.circuitId());
            }
            if (entry.remoteId() != null && !entry.remoteId().isBlank()) {
                option82.setAgentRemoteId(entry.remoteId());
            }
            if (log.isTraceEnabled()) {
                log.trace("adding option82 {} ", option82);
            }
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
                    .filter(option -> option
                            .getCode() != DHCP.DHCPOptionCode.OptionCode_CircuitID
                                    .getValue())
                    .collect(Collectors.toList());

            return dhcpPacket.setOptions(newoptions);
        }

        /**
         * Returns the circuit Id values decoded from the option 82 data. Decoding
         * is performed if and only if the circuit id format is in the form
         * "{@literal<}connectPoint>:vlan{@literal<}clientVlanId>:pcp{@literal<}downstreamPcp>"
         *
         * @param cktId the circuitId string from option 82 data
         * @return decoded circuit id data if it is in the expected format or
         *         null
         */
        private RelayToClientInfo decodeCircuitId(String cktId) {
            if (cktId.contains(VLAN_KEYWORD) && cktId.contains(PCP_KEYWORD)) {
                ConnectPoint cp = ConnectPoint
                        .fromString(cktId
                                .substring(0, cktId.indexOf(VLAN_KEYWORD)));
                VlanId cvid = VlanId
                        .vlanId(cktId.substring(
                                                cktId.indexOf(VLAN_KEYWORD)
                                                        + VLAN_KEYWORD.length(),
                                                cktId.indexOf(PCP_KEYWORD)));
                int pcp = Integer
                        .valueOf(cktId.substring(cktId.indexOf(PCP_KEYWORD)
                                + PCP_KEYWORD.length()))
                        .intValue();
                log.debug("retrieved from option82-> cp={} cvlan={} down-pcp={}"
                        + " for relaying to client ", cp, cvid, pcp);
                return new RelayToClientInfo(cp, cvid, pcp, cktId);
            } else {
                log.debug("Option 82 circuitId {} is operator defined and will "
                        + "not be used for forwarding", cktId);
                return null;
            }
        }

        private class RelayToClientInfo {
            Ethernet ethernetPkt;
            ConnectPoint cp;
            VlanId cvid;
            int pcp;
            String cktId;

            public RelayToClientInfo(ConnectPoint cp, VlanId cvid, int pcp,
                                     String cktId) {
                this.cp = cp;
                this.cvid = cvid;
                this.pcp = pcp;
                this.cktId = cktId;
            }

            public RelayToClientInfo() {
            }

            @Override
            public String toString() {
                return "RelayToClientInfo: {connectPoint=" + cp + " clientVlan="
                        + cvid + " clientPcp=" + pcp + " circuitId=" + cktId + "}";
            }

        }

        // get the type of the DHCP packet
        private DHCP.MsgType getDhcpPacketType(DHCP dhcpPayload) {
            for (DhcpOption option : dhcpPayload.getOptions()) {
                if (option.getCode() == OptionCode_MessageType.getValue()) {
                    byte[] data = option.getData();
                    return DHCP.MsgType.getType(data[0]);
                }
            }
            return null;
        }

        private void updateDhcpRelayCountersStore(SubscriberAndDeviceInformation entry,
                                                  DhcpL2RelayCounterNames counterType) {
            // Update global counter stats
            dhcpL2RelayCounters.incrementCounter(DhcpL2RelayEvent.GLOBAL_COUNTER,
                                                 counterType);
            if (entry == null) {
                log.warn("Counter not updated as subscriber info not found.");
            } else {
                // Update subscriber counter stats
                dhcpL2RelayCounters.incrementCounter(entry.id(), counterType);
            }
        }

        /**
         * Get subscriber information based on subscriber's connectPoint.
         *
         * @param subsCp the subscriber's connectPoint
         * @return subscriber sadis info or null if not found
         */
        private SubscriberAndDeviceInformation getSubscriber(ConnectPoint subsCp) {
            if (subsCp != null) {
                String portName = getPortName(subsCp);
                return getSubscriberAndDeviceInfo(portName);
            }
            return null;
        }

        /**
         * Returns sadis info for subscriber based on incoming packet context.
         * The packet context must refer to a packet coming from a subscriber
         * port.
         *
         * @param context incoming packet context from subscriber port (UNI)
         * @return sadis info for the subscriber or null
         */
        private SubscriberAndDeviceInformation getSubscriber(PacketContext context) {
            String portName = getPortName(context.inPacket().receivedFrom());
            return getSubscriberAndDeviceInfo(portName);
        }

        /**
         * Returns ConnectPoint of the Client based on MAC address and C-VLAN.
         * Verifies that returned connect point has service defined in sadis.
         *
         * @param dstMac client dstMac
         * @param context context for incoming packet, parsed for C-vlan id
         * @return connect point information for client or null if connect point
         *         not found or service cannot be verified for client info
         */
        private ConnectPoint getConnectPointOfClient(MacAddress dstMac,
                                                     PacketContext context) {
            Set<Host> hosts = hostService.getHostsByMac(dstMac);
            if (hosts == null || hosts.isEmpty()) {
                log.warn("Cannot determine host for DHCP client: {}. Aborting "
                                 + "relay for DHCP Packet from server", dstMac);
                return null;
            }
            for (Host h : hosts) {
                // if more than one (for example, multiple services with same
                // mac-address but different service VLANs (inner/C vlans)
                // find the connect point which has an valid entry in SADIS
                ConnectPoint cp = new ConnectPoint(h.location().deviceId(),
                                                   h.location().port());

                SubscriberAndDeviceInformation sub = getSubscriber(cp);
                if (sub == null) {
                    log.warn("Subscriber info not found for {} for host {}", cp, h);
                    continue;
                }
                // check for cvlan in subscriber's uniTagInfo list
                UniTagInformation uniTagInformation =
                        getUnitagInformationFromPacketContext(context, sub);
                if (uniTagInformation != null) {
                    return cp;
                }
            }
            // no sadis config found for this connectPoint/vlan
            log.warn("Missing service information for dhcp packet received from"
                    + " {} with cTag {} .. cannot relay to client",
                     context.inPacket().receivedFrom(),
                     context.inPacket().parsed().getVlanID());
            return null;
        }

        /**
         * Returns the port-name for the given connectPoint port.
         *
         * @param cp the given connect point
         * @return the port-name for the connect point port
         */
        private String getPortName(ConnectPoint cp) {
            Port p = deviceService.getPort(cp);
            return p.annotations().value(AnnotationKeys.PORT_NAME);
        }

        /**
         * Return's uniTagInformation (service information) if incoming packet's
         * client VLAN id matches the subscriber's service info, and dhcp is
         * required for this service.
         *
         * @param context
         * @param sub
         * @return
         */
        private UniTagInformation getUnitagInformationFromPacketContext(PacketContext context,
                                                                        SubscriberAndDeviceInformation sub) {
            // If the ctag is defined in the tagList and dhcp is required,
            // return the service info
            List<UniTagInformation> tagList = sub.uniTagList();
            for (UniTagInformation uniServiceInformation : tagList) {
                if (uniServiceInformation.getPonCTag().toShort() == context.inPacket()
                        .parsed().getVlanID()) {
                    if (uniServiceInformation.getIsDhcpRequired()) {
                        return uniServiceInformation;
                    }
                }
            }

            return null;
        }


        private MacAddress relayAgentMacAddress(PacketContext context) {
            SubscriberAndDeviceInformation device = this.getDevice(context);
            if (device == null) {
                log.warn("Device not found for {}", context.inPacket().receivedFrom());
                return null;
            }
            return device.hardwareIdentifier();
        }

        /**
         * Returns sadis information for device from which packet was received.
         *
         * @param context the packet context
         * @return sadis information for device
         */
        private SubscriberAndDeviceInformation getDevice(PacketContext context) {
            String serialNo = deviceService
                    .getDevice(context.inPacket().receivedFrom().deviceId())
                    .serialNumber();
            return getSubscriberAndDeviceInfo(serialNo);
        }

    }

    /**
     * Listener for network config events.
     */
    private class InternalConfigListener implements NetworkConfigListener {

        @Override
        public void event(NetworkConfigEvent event) {
            eventHandlerExecutor.submit(() -> handleNetworkConfigEventEvent(event));
        }

        private void handleNetworkConfigEventEvent(NetworkConfigEvent event) {
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
            eventHandlerExecutor.submit(() -> handleMastershipEvent(event));
        }

        private void handleMastershipEvent(MastershipEvent event) {
            if (!useOltUplink) {
                if (dhcpServerConnectPoint.get() != null &&
                        dhcpServerConnectPoint.get().deviceId().
                                equals(event.subject())) {
                    log.trace("Mastership Event received for {}", event.subject());
                    // mastership of the device for our connect point has changed
                    // reselect
                    selectServerConnectPoint();
                }
            }
        }
    }

    private void removeAllocations(Predicate<Map.Entry<String, Versioned<DhcpAllocationInfo>>> pred) {
        allocations.stream()
                .filter(pred)
                .map(Map.Entry::getKey)
                .collect(Collectors.toList())
                .forEach(allocations::remove);
    }

    @Override
    public void clearAllocations() {
        allocations.clear();
    }

    @Override
    public boolean removeAllocationsByConnectPoint(ConnectPoint cp) {
        boolean removed = false;
        for (String key : allocations.keySet()) {
            DhcpAllocationInfo entry = allocations.asJavaMap().get(key);
            if (entry.location().equals(cp)) {
                allocations.remove(key);
                removed = true;
            }
        }
        return removed;
    }

    /**
     * Checks for mastership or falls back to leadership on deviceId.
     * If the device is available use mastership,
     * otherwise fallback on leadership.
     * Leadership on the device topic is needed because the master can be NONE
     * in case the device went away, we still need to handle events
     * consistently
     */
    private boolean isLocalLeader(DeviceId deviceId) {
        if (deviceService.isAvailable(deviceId)) {
            return mastershipService.isLocalMaster(deviceId);
        } else {
            // Fallback with Leadership service - device id is used as topic
            NodeId leader = leadershipService.runForLeadership(
                    deviceId.toString()).leaderNodeId();
            // Verify if this node is the leader
            return clusterService.getLocalNode().id().equals(leader);
        }
    }

    /**
     * Handles Device status change for the devices which connect
     * to the DHCP server.
     */
    private class InnerDeviceListener implements DeviceListener {
        @Override
        public void event(DeviceEvent event) {
            eventHandlerExecutor.submit(() -> handleDeviceEvent(event));
        }

        private void handleDeviceEvent(DeviceEvent event) {
            final DeviceId deviceId = event.subject().id();

            // Ensure only one instance handles the event
            if (!isLocalLeader(deviceId)) {
                return;
            }
            // ignore stats
            if (event.type().equals(DeviceEvent.Type.PORT_STATS_UPDATED)) {
                return;
            }

            log.debug("Device Event received for {} event {}", event.subject(),
                      event.type());

            switch (event.type()) {
                case DEVICE_REMOVED:
                    log.info("Device removed {}", event.subject().id());
                    removeAllocations(e -> e.getValue().value().location().deviceId().equals(deviceId));
                    break;
                case DEVICE_AVAILABILITY_CHANGED:
                    boolean available = deviceService.isAvailable(deviceId);
                    log.info("Device Avail Changed {} to {}", event.subject().id(), available);

                    if (!available && deviceService.getPorts(deviceId).isEmpty()) {
                        removeAllocations(e -> e.getValue().value().location().deviceId().equals(deviceId));
                        log.info("Device {} is removed from DHCP allocationmap ", deviceId);
                    }
                    break;
                case PORT_REMOVED:
                    Port port = event.port();
                    log.info("Port {} is deleted on device {}", port, deviceId);

                    ConnectPoint cp = new ConnectPoint(deviceId, port.number());
                    removeAllocations(e -> e.getValue().value().location().equals(cp));

                    log.info("Port {} on device {} is removed from DHCP allocationmap", event.port(), deviceId);
                    break;
                default:
                    break;
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
                                    Optional.empty());
                        }
                        break;
                    default:
                        break;
                }
            }
        }
    }

    private class InnerDhcpL2RelayStoreDelegate implements DhcpL2RelayStoreDelegate {
        @Override
        public void notify(DhcpL2RelayEvent event) {
            if (event.type().equals(DhcpL2RelayEvent.Type.STATS_UPDATE)) {
                DhcpL2RelayEvent toPost = event;
                if (event.getSubscriberId() != null) {
                    // infuse the event with the allocation info before posting
                    DhcpAllocationInfo info = Versioned.valueOrNull(allocations.get(event.getSubscriberId()));
                    toPost = new DhcpL2RelayEvent(event.type(), info, event.connectPoint(),
                                                  event.getCountersEntry(), event.getSubscriberId());
                }
                post(toPost);
            }

        }
    }
}
