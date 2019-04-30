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
package org.opencord.dhcpl2relay.impl.packet;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Represents the DHCP Option 82 information. Currently only supports
 * sub option 1 (agent-circuit-id) and 2 (agent=-relay-id).
 */
public class DhcpOption82 {

    private String agentCircuitId = null;
    private String agentRemoteId = null;

    public DhcpOption82() {

    }

    public void setAgentCircuitId(String value) {
        this.agentCircuitId = value;
    }

    /**
     *
     * @return agentCircuitId
     */
    public String getAgentCircuitId() {
        return this.agentCircuitId;
    }

    /**
     * sets AgentRemoteId.
     * @param value   Value to be set
     */
    public void setAgentRemoteId(String value) {
        this.agentRemoteId = value;
    }

    /**
     *
     * @return agentRemoteId
     */
    public String getAgentRemoteId() {
        return this.agentRemoteId;
    }

    /**
     *
     * @return length of option 82.
     */
    public byte length() {
        int length = 0;

        // +2 below for sub option ID and length of sub option
        if (agentCircuitId != null) {
            length += agentCircuitId.length() + 2;
        }
        if (agentRemoteId != null) {
            length += agentRemoteId.length() + 2;
        }
        return (byte) length;
    }

    /**
     * Returns the representation of the option 82 specification as a byte
     * array.
     * @return returns byte array
     */
    public byte[] toByteArray() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        // Add sub option if set
        if (agentCircuitId != null) {
            buf.write((byte) 1);
            buf.write((byte) agentCircuitId.length());
            byte[] bytes = agentCircuitId.getBytes(StandardCharsets.UTF_8);
            buf.write(bytes, 0, bytes.length);
        }

        // Add sub option if set
        if (agentRemoteId != null) {
            buf.write((byte) 2);
            buf.write((byte) agentRemoteId.length());
            byte[] bytes = agentRemoteId.getBytes(StandardCharsets.UTF_8);
            buf.write(bytes, 0, bytes.length);
        }

        return buf.toByteArray();
    }

}
