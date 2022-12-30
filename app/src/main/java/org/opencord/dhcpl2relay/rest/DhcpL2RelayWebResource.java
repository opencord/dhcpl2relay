/*
 * Copyright 2022-2023 Open Networking Foundation (ONF) and the ONF Contributors
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
package org.opencord.dhcpl2relay.rest;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.Objects;
import java.util.stream.Collectors;
import java.util.Map;
import java.util.Map.Entry;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;

import org.onosproject.net.DeviceId;
import org.onosproject.rest.AbstractWebResource;

import org.opencord.dhcpl2relay.DhcpAllocationInfo;
import org.opencord.dhcpl2relay.DhcpL2RelayService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static javax.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR;

/**
 * DhcpL2Relay web resource.
 */
@Path("app")
public class DhcpL2RelayWebResource extends AbstractWebResource {
    private final ObjectNode root = mapper().createObjectNode();
    private final ArrayNode node = root.putArray("entries");
    private final Logger log = LoggerFactory.getLogger(getClass());

    private static final String SUBSCRIBER_ID = "subscriberId";
    private static final String CONNECT_POINT = "connectPoint";
    private static final String MAC_ADDRESS = "macAddress";
    private static final String STATE = "state";
    private static final String VLAN_ID = "vlanId";
    private static final String CIRCUIT_ID = "circuitId";
    private static final String IP_ALLOCATED = "ipAllocated";
    private static final String ALLOCATION_TIMESTAMP = "allocationTimestamp";

    /**
     *
     * Shows all the successful DHCP allocations relayed by the dhcpl2relay.
     *
     * @return 200 OK
     */
    @GET
    @Path("/allocations")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAllocations() {
       return getAllocations(null);
    }

    /**
     * Shows the successful DHCP allocations relayed by the dhcpl2relay for a specific access device.
     *
     * @param deviceId Access device ID.
     *
     * @return 200 OK
     */
    @GET
    @Path("/allocations/{deviceId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAllocation(@PathParam("deviceId") String deviceId) {
        return getAllocations(deviceId);
    }

    private Response getAllocations(String deviceId) {
        DhcpL2RelayService service = get(DhcpL2RelayService.class);
        Map<String, DhcpAllocationInfo> allocations = service.getAllocationInfo();

        try {
            buildAllocationsNodeObject(allocations, deviceId);
            return ok(mapper().writeValueAsString(root)).build();
        } catch (Exception e) {
            log.error("Error while fetching DhcpL2Relay allocations information through REST API: {}", e.getMessage());
            return Response.status(INTERNAL_SERVER_ERROR).build();
        }
    }

    private void buildAllocationsNodeObject(Map<String, DhcpAllocationInfo> allocationMap, String strDeviceId) {
        if (Objects.nonNull(strDeviceId)) {
            DeviceId deviceId = DeviceId.deviceId(strDeviceId);
            allocationMap = allocationMap.entrySet().stream()
                    .filter(a -> a.getValue().location().deviceId().equals(deviceId))
                    .collect(Collectors.toMap(Entry::getKey, Entry::getValue));
        }

        allocationMap.forEach((key, value) -> {
            node.add(encodeDhcpAllocationInfo(value));
        });
    }

    private ObjectNode encodeDhcpAllocationInfo(DhcpAllocationInfo entry) {
        return mapper().createObjectNode()
                .put(SUBSCRIBER_ID, entry.subscriberId())
                .put(CONNECT_POINT, entry.location().toString())
                .put(STATE, entry.type().toString())
                .put(MAC_ADDRESS, entry.macAddress().toString())
                .put(VLAN_ID, entry.vlanId().toShort())
                .put(CIRCUIT_ID, entry.circuitId())
                .put(IP_ALLOCATED, entry.ipAddress().getIp4Address().toString())
                .put(ALLOCATION_TIMESTAMP, entry.allocationTime().toString());
    }
}
