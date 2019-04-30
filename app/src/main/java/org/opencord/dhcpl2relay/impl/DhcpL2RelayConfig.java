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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

import com.google.common.collect.ImmutableSet;

import org.onosproject.core.ApplicationId;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.config.Config;

import java.util.HashSet;
import java.util.Set;


/**
 * DHCP Relay Config class.
 */
public class DhcpL2RelayConfig extends Config<ApplicationId> {

    private static final String DHCP_CONNECT_POINTS = "dhcpServerConnectPoints";
    private static final String MODIFY_SRC_DST_MAC  = "modifyUlPacketsSrcDstMacAddresses";
    private static final String USE_OLT_ULPORT_FOR_PKT_INOUT = "useOltUplinkForServerPktInOut";

    private static final Boolean DEFAULT_MODIFY_SRC_DST_MAC = false;
    private static final Boolean DEFAULT_USE_OLT_ULPORT_FOR_PKT_INOUT = false;

    @Override
    public boolean isValid() {

        return hasOnlyFields(DHCP_CONNECT_POINTS, MODIFY_SRC_DST_MAC,
                USE_OLT_ULPORT_FOR_PKT_INOUT);
    }

    /**
     * Returns whether the app would use the uplink port of OLT for sending/receving
     * messages to/from the server.
     *
     * @return true if OLT uplink port is to be used, false otherwise
     */
    public boolean getUseOltUplinkForServerPktInOut() {
        if (object == null) {
            return DEFAULT_USE_OLT_ULPORT_FOR_PKT_INOUT;
        }
        if (!object.has(USE_OLT_ULPORT_FOR_PKT_INOUT)) {
            return DEFAULT_USE_OLT_ULPORT_FOR_PKT_INOUT;
        }

        return object.path(USE_OLT_ULPORT_FOR_PKT_INOUT).asBoolean();
    }

    /**
     * Returns whether the app would modify MAC address of uplink packets.
     *
     * @return whether app would modify src and dst MAC addresses or not of packets
     *         sent to the DHCP server
     */
    public boolean getModifySrcDstMacAddresses() {
        if (object == null) {
            return DEFAULT_MODIFY_SRC_DST_MAC;
        }
        if (!object.has(MODIFY_SRC_DST_MAC)) {
            return DEFAULT_MODIFY_SRC_DST_MAC;
        }

        return object.path(MODIFY_SRC_DST_MAC).asBoolean();
    }

    /**
     * Returns the dhcp server connect points.
     *
     * @return dhcp server connect points
     */
    public Set<ConnectPoint> getDhcpServerConnectPoint() {
        if (object == null) {
            return new HashSet<ConnectPoint>();
        }

        if (!object.has(DHCP_CONNECT_POINTS)) {
            return ImmutableSet.of();
        }

        ImmutableSet.Builder<ConnectPoint> builder = ImmutableSet.builder();
        ArrayNode arrayNode = (ArrayNode) object.path(DHCP_CONNECT_POINTS);
        for (JsonNode jsonNode : arrayNode) {
            String portName = jsonNode.asText(null);
            if (portName == null) {
                return null;
            }
            try {
                builder.add(ConnectPoint.deviceConnectPoint(portName));
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
        return builder.build();
    }
}
