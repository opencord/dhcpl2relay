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

    @Override
    public boolean isValid() {

        return hasOnlyFields(DHCP_CONNECT_POINTS);
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
