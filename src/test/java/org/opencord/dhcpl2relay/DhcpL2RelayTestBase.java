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

import org.onlab.packet.BasePacket;
import org.onlab.packet.DHCP;
import org.onlab.packet.DHCPOption;
import org.onlab.packet.DHCPPacketType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.MacAddress;
import org.onlab.packet.UDP;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.packet.DefaultInboundPacket;
import org.onosproject.net.packet.DefaultPacketContext;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketServiceAdapter;

import org.opencord.dhcpl2relay.packet.DhcpEthernet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import static org.junit.Assert.fail;


/**
 * Common methods for AAA app testing.
 */
public class DhcpL2RelayTestBase {
    private final Logger log = LoggerFactory.getLogger(getClass());

    private static final int TRANSACTION_ID = 1000;

    private static final String EXPECTED_IP = "10.2.0.2";

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
                DhcpEthernet eth = DhcpEthernet.deserializer().deserialize(packet.data().array(),
                        0, packet.data().array().length);
                savePacket(eth);
            } catch (Exception e) {
                fail(e.getMessage());
            }
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

    /**
     * Sends an Ethernet packet to the process method of the Packet Processor.
     *
     * @param pkt Ethernet packet
     */
    void sendPacket(DhcpEthernet pkt, ConnectPoint cp) {
        final ByteBuffer byteBuffer = ByteBuffer.wrap(pkt.serialize());
        InboundPacket inPacket = new DefaultInboundPacket(cp, null, byteBuffer);

        PacketContext context = new TestPacketContext(127L, inPacket, null, false);
        packetProcessor.process(context);
    }

    /**
     * Constructs an Ethernet packet with IP/UDP/DHCP payload.
     *
     * @return Ethernet packet
     */
    private DhcpEthernet construcEthernetPacket(MacAddress srcMac, MacAddress dstMac,
                                                String dstIp, byte dhcpReqRsp,
                                                MacAddress clientHwAddress,
                                                Ip4Address dhcpClientIpAddress) {
        // Ethernet Frame.
        DhcpEthernet ethPkt = new DhcpEthernet();
        ethPkt.setSourceMacAddress(srcMac);
        ethPkt.setDestinationMacAddress(dstMac);
        ethPkt.setEtherType(Ethernet.TYPE_IPV4);
        ethPkt.setVlanID((short) 2);
        ethPkt.setPriorityCode((byte) 6);

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
    DhcpEthernet constructDhcpDiscoverPacket(MacAddress clientMac) {

        DhcpEthernet pkt = construcEthernetPacket(clientMac, MacAddress.BROADCAST,
                "255.255.255.255", DHCP.OPCODE_REQUEST, MacAddress.NONE,
                Ip4Address.valueOf("0.0.0.0"));

        IPv4 ipv4Packet = (IPv4) pkt.getPayload();
        UDP udpPacket = (UDP) ipv4Packet.getPayload();
        DHCP dhcpPacket = (DHCP) udpPacket.getPayload();

        dhcpPacket.setOptions(constructDhcpOptions(DHCPPacketType.DHCPDISCOVER));

        return pkt;
    }

    /**
     * Constructs DHCP Request Packet.
     *
     * @return Ethernet packet
     */
    DhcpEthernet constructDhcpRequestPacket(MacAddress clientMac) {

        DhcpEthernet pkt = construcEthernetPacket(clientMac, MacAddress.BROADCAST,
                "255.255.255.255", DHCP.OPCODE_REQUEST, MacAddress.NONE,
                Ip4Address.valueOf("0.0.0.0"));

        IPv4 ipv4Packet = (IPv4) pkt.getPayload();
        UDP udpPacket = (UDP) ipv4Packet.getPayload();
        DHCP dhcpPacket = (DHCP) udpPacket.getPayload();

        dhcpPacket.setOptions(constructDhcpOptions(DHCPPacketType.DHCPREQUEST));

        return pkt;
    }

    /**
     * Constructs DHCP Offer Packet.
     *
     * @return Ethernet packet
     */
    DhcpEthernet constructDhcpOfferPacket(MacAddress servMac, MacAddress clientMac,
                                           String ipAddress, String dhcpClientIpAddress) {

        DhcpEthernet pkt = construcEthernetPacket(servMac, clientMac, ipAddress, DHCP.OPCODE_REPLY,
                clientMac, Ip4Address.valueOf(dhcpClientIpAddress));

        IPv4 ipv4Packet = (IPv4) pkt.getPayload();
        UDP udpPacket = (UDP) ipv4Packet.getPayload();
        DHCP dhcpPacket = (DHCP) udpPacket.getPayload();

        dhcpPacket.setOptions(constructDhcpOptions(DHCPPacketType.DHCPOFFER));

        return pkt;
    }

    /**
     * Constructs DHCP Ack Packet.
     *
     * @return Ethernet packet
     */
    DhcpEthernet constructDhcpAckPacket(MacAddress servMac, MacAddress clientMac,
                                           String ipAddress, String dhcpClientIpAddress) {

        DhcpEthernet pkt = construcEthernetPacket(servMac, clientMac, ipAddress, DHCP.OPCODE_REPLY,
                clientMac, Ip4Address.valueOf(dhcpClientIpAddress));

        IPv4 ipv4Packet = (IPv4) pkt.getPayload();
        UDP udpPacket = (UDP) ipv4Packet.getPayload();
        DHCP dhcpPacket = (DHCP) udpPacket.getPayload();

        dhcpPacket.setOptions(constructDhcpOptions(DHCPPacketType.DHCPACK));

        return pkt;
    }

    /**
     * Constructs DHCP Discover Options.
     *
     * @return Ethernet packet
     */
    private List<DHCPOption> constructDhcpOptions(DHCPPacketType packetType) {

        // DHCP Options.
        DHCPOption option = new DHCPOption();
        List<DHCPOption> optionList = new ArrayList<>();


        // DHCP Message Type.
        option.setCode(DHCP.DHCPOptionCode.OptionCode_MessageType.getValue());
        option.setLength((byte) 1);
        byte[] optionData = {(byte) packetType.getValue()};
        option.setData(optionData);
        optionList.add(option);

        // DHCP Requested IP.
        option = new DHCPOption();
        option.setCode(DHCP.DHCPOptionCode.OptionCode_RequestedIP.getValue());
        option.setLength((byte) 4);
        optionData = Ip4Address.valueOf(EXPECTED_IP).toOctets();
        option.setData(optionData);
        optionList.add(option);

        // End Option.
        option = new DHCPOption();
        option.setCode(DHCP.DHCPOptionCode.OptionCode_END.getValue());
        option.setLength((byte) 1);
        optionList.add(option);

        return optionList;
    }
}
