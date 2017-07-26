/*
 * Copyright 2017-present Open Networking Laboratory
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
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Modified;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onlab.packet.DHCP;
import org.onlab.packet.DHCPOption;
import org.onlab.packet.DHCPPacketType;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.IPv4;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
import org.onlab.packet.VlanId;

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
import java.util.Set;
import java.util.Optional;

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

    @Property(name = "option82", boolValue = true,
            label = "Add option 82 to relayed packets")
    protected boolean option82 = true;

    private DhcpRelayPacketProcessor dhcpRelayPacketProcessor =
            new DhcpRelayPacketProcessor();


    private ConnectPoint dhcpServerConnectPoint = null;
    private MacAddress dhcpConnectMac = MacAddress.BROADCAST;
    private ApplicationId appId;

    @Activate
    protected void activate(ComponentContext context) {
        //start the dhcp relay agent
        appId = coreService.registerApplication(DHCP_L2RELAY_APP);
        componentConfigService.registerProperties(getClass());

        cfgService.addListener(cfgListener);
        factories.forEach(cfgService::registerConfigFactory);
        //update the dhcp server configuration.
        updateConfig();
        //add the packet services.
        packetService.addProcessor(dhcpRelayPacketProcessor,
                PacketProcessor.director(0));
        requestDhcpPackets();
        modified(context);

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
        return dhcpServerConnectPoint != null;
    }

    private void updateConfig() {
        DhcpL2RelayConfig cfg = cfgService.getConfig(appId, DhcpL2RelayConfig.class);
        if (cfg == null) {
            log.warn("Dhcp Server info not available");
            return;
        }

        dhcpServerConnectPoint = cfg.getDhcpServerConnectPoint();
        log.info("dhcp server connect point: " + dhcpServerConnectPoint);
    }

    /**
     * Request DHCP packet in via PacketService.
     */
    private void requestDhcpPackets() {
        if (dhcpServerConnectPoint != null) {
            TrafficSelector.Builder selectorServer = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPProtocol(IPv4.PROTOCOL_UDP)
                    .matchUdpSrc(TpPort.tpPort(UDP.DHCP_SERVER_PORT));
            packetService.requestPackets(selectorServer.build(),
                    PacketPriority.CONTROL, appId,
                    Optional.of(dhcpServerConnectPoint.deviceId()));

            TrafficSelector.Builder selectorClient = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPProtocol(IPv4.PROTOCOL_UDP)
                    .matchUdpSrc(TpPort.tpPort(UDP.DHCP_CLIENT_PORT));
            packetService.requestPackets(selectorClient.build(),
                    PacketPriority.CONTROL, appId,
                    Optional.of(dhcpServerConnectPoint.deviceId()));
        }
    }

    /**
     * Cancel requested DHCP packets in via packet service.
     */
    private void cancelDhcpPackets() {
        if (dhcpServerConnectPoint != null) {
            TrafficSelector.Builder selectorServer = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPProtocol(IPv4.PROTOCOL_UDP)
                    .matchUdpSrc(TpPort.tpPort(UDP.DHCP_SERVER_PORT));
            packetService.cancelPackets(selectorServer.build(),
                    PacketPriority.CONTROL, appId,
                    Optional.of(dhcpServerConnectPoint.deviceId()));

            TrafficSelector.Builder selectorClient = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPProtocol(IPv4.PROTOCOL_UDP)
                    .matchUdpSrc(TpPort.tpPort(UDP.DHCP_CLIENT_PORT));
            packetService.cancelPackets(selectorClient.build(),
                    PacketPriority.CONTROL, appId,
                    Optional.of(dhcpServerConnectPoint.deviceId()));
        }
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
    private Ip4Address relayAgentIPv4Address(ConnectPoint cp) {

        SubscriberAndDeviceInformation device = getDevice(cp);
        if (device == null) {
            log.warn("Device not found for {}", cp);
            return null;
        }

        return device.ipAddress();
    }

    private MacAddress relayAgentMacAddress(PacketContext context) {

        SubscriberAndDeviceInformation device = getDevice(context);
        if (device == null) {
            log.warn("Device not found for {}", context.inPacket().
                    receivedFrom());
            return null;
        }

        return device.hardwareIdentifier();
    }

    private String nasPortId(PacketContext context) {
        Port p = deviceService.getPort(context.inPacket().receivedFrom());

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

            //log.info("Got a packet of type {}", packet.getEtherType());

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
        private void forwardPacket(Ethernet packet) {

            if (dhcpServerConnectPoint != null) {
                TrafficTreatment t = DefaultTrafficTreatment.builder()
                        .setOutput(dhcpServerConnectPoint.port()).build();
                OutboundPacket o = new DefaultOutboundPacket(
                        dhcpServerConnectPoint.deviceId(), t,
                        ByteBuffer.wrap(packet.serialize()));
                if (log.isTraceEnabled()) {
                    log.trace("Relaying packet to dhcp server {} at {}",
                            packet, dhcpServerConnectPoint);
                }
                packetService.emit(o);
            } else {
                log.warn("No dhcp server connect point");
            }
        }

        //process the dhcp packet before sending to server
        private void processDhcpPacket(PacketContext context, Ethernet packet,
                                       DHCP dhcpPayload) {
            if (dhcpPayload == null) {
                log.warn("DHCP payload is null");
                return;
            }

            DHCPPacketType incomingPacketType = null;
            for (DHCPOption option : dhcpPayload.getOptions()) {
                if (option.getCode() == OptionCode_MessageType.getValue()) {
                    byte[] data = option.getData();
                    incomingPacketType = DHCPPacketType.getType(data[0]);
                }
            }
            log.info("Received DHCP Packet of type {}", incomingPacketType);
            log.trace("Processing Packet {}", packet);

            switch (incomingPacketType) {
            case DHCPDISCOVER:
                Ethernet ethernetPacketDiscover =
                    processDhcpPacketFromClient(context, packet);
                if (ethernetPacketDiscover != null) {
                    forwardPacket(ethernetPacketDiscover);
                }
                break;
            case DHCPOFFER:
                //reply to dhcp client.
                Ethernet ethernetPacketOffer = processDhcpPacketFromServer(packet);
                if (ethernetPacketOffer != null) {
                    sendReply(ethernetPacketOffer, dhcpPayload);
                }
                break;
            case DHCPREQUEST:
                Ethernet ethernetPacketRequest =
                    processDhcpPacketFromClient(context, packet);
                if (ethernetPacketRequest != null) {
                    forwardPacket(ethernetPacketRequest);
                }
                break;
            case DHCPACK:
                //reply to dhcp client.
                Ethernet ethernetPacketAck = processDhcpPacketFromServer(packet);
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
            log.info("Processing packet from client");

            MacAddress relayAgentMac = relayAgentMacAddress(context);
            if (relayAgentMac == null) {
                log.warn("RelayAgent MAC not found ");

                return null;
            }

            Ethernet etherReply = ethernetPacket;

            IPv4 ipv4Packet = (IPv4) etherReply.getPayload();
            UDP udpPacket = (UDP) ipv4Packet.getPayload();
            DHCP dhcpPacket = (DHCP) udpPacket.getPayload();

            etherReply.setSourceMACAddress(relayAgentMac);
            etherReply.setDestinationMACAddress(dhcpConnectMac);

            etherReply.setVlanID(cTag(context).toShort());
            etherReply.setQinQTPID(Ethernet.TYPE_VLAN);
            etherReply.setQinQVID(sTag(context).toShort());

            log.info("Finished processing");
            return etherReply;
        }

        //build the DHCP offer/ack with proper client port.
        private Ethernet processDhcpPacketFromServer(Ethernet ethernetPacket) {
            log.warn("Processing DHCP packet from server");
            // get dhcp header.
            Ethernet etherReply = (Ethernet) ethernetPacket.clone();
            IPv4 ipv4Packet = (IPv4) etherReply.getPayload();
            UDP udpPacket = (UDP) ipv4Packet.getPayload();
            DHCP dhcpPayload = (DHCP) udpPacket.getPayload();


            MacAddress dstMac = valueOf(dhcpPayload.getClientHardwareAddress());
            Set<Host> hosts = hostService.getHostsByMac(dstMac);
            if (hosts == null || hosts.isEmpty()) {
                log.warn("Cannot determine host for DHCP client: {}. Aborting "
                        + "relay for dhcp packet from server {}",
                         dstMac, ethernetPacket);
                return null;
            } else if (hosts.size() > 1) {
                // XXX  redo to send reply to all hosts found
                log.warn("Multiple hosts found for mac:{}. Picking one "
                        + "host out of {}", dstMac, hosts);
            }
            Host host = hosts.iterator().next();

            etherReply.setDestinationMACAddress(dstMac);
            etherReply.setQinQVID(Ethernet.VLAN_UNTAGGED);
            etherReply.setPriorityCode(ethernetPacket.getPriorityCode());
            etherReply.setVlanID((short) 0);

            // we leave the srcMac from the original packet

            // figure out the relay agent IP corresponding to the original request
            Ip4Address relayAgentIP = relayAgentIPv4Address(
                    new ConnectPoint(host.location().deviceId(),
                            host.location().port()));
            if (relayAgentIP == null) {
                log.warn("Cannot determine relay agent Ipv4 addr for host {}. "
                        + "Aborting relay for dhcp packet from server {}",
                        host, ethernetPacket);
                return null;
            }

            ipv4Packet.setSourceAddress(relayAgentIP.toInt());
            ipv4Packet.setDestinationAddress(dhcpPayload.getYourIPAddress());

            udpPacket.setDestinationPort(UDP.DHCP_CLIENT_PORT);
            udpPacket.setPayload(dhcpPayload);
            ipv4Packet.setPayload(udpPacket);
            etherReply.setPayload(ipv4Packet);

            log.info("Finished processing packet");
            return etherReply;
        }

        //send the response to the requester host.
        private void sendReply(Ethernet ethPacket, DHCP dhcpPayload) {
            MacAddress descMac = valueOf(dhcpPayload.getClientHardwareAddress());
            Host host = hostService.getHostsByMac(descMac).stream().findFirst().orElse(null);

            // Send packet out to requester if the host information is available
            if (host != null) {
                log.info("Sending DHCP packet to host: {}", host);
                TrafficTreatment t = DefaultTrafficTreatment.builder()
                        .setOutput(host.location().port()).build();
                OutboundPacket o = new DefaultOutboundPacket(
                        host.location().deviceId(), t, ByteBuffer.wrap(ethPacket.serialize()));
                if (log.isTraceEnabled()) {
                    log.trace("Relaying packet to dhcp client {}", ethPacket);
                }
                packetService.emit(o);
                log.error("DHCP Packet sent to {}", host.location());
            } else {
                log.info("Dropping DHCP packet because can't find host for {}", descMac);
            }
        }
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
}
