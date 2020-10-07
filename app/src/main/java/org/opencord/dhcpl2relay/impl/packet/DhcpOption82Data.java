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
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents the DHCP Option 82 sub-options. Currently only supports sub option
 * 1 (agent-circuit-id) and 2 (agent-remote-id).
 */
public class DhcpOption82Data {

    private String agentCircuitId = null;
    private String agentRemoteId = null;
    private final Logger log = LoggerFactory.getLogger(getClass());
    public static final byte CIRCUIT_ID_CODE = 1;
    public static final byte REMOTE_ID_CODE = 2;

    public DhcpOption82Data() {

    }

    /**
     * Constructs a DhcpOption82Data object from the given byte array. The
     * expectation is that the byte array starts with the first suboption (i.e
     * it does not include the option-code and overall length of the option 82)
     *
     * @param b byte array representing the data portion of the dhcp option 82
     */
    public DhcpOption82Data(byte[] b) {
        ByteBuffer bb = ByteBuffer.wrap(b, 0, b.length);
        if (b.length < 3) {
            log.warn("Malformed option82 sub-options {}", b);
            return;
        }
        while (bb.hasRemaining() && bb.limit() - bb.position() > 2) {
            byte subOptionCode = bb.get();
            byte subOptionLen = bb.get();
            byte[] subOptionData = new byte[subOptionLen];
            try {
                bb.get(subOptionData);
            } catch (BufferUnderflowException e) {
                log.warn("Malformed option82 sub-option {}", e.getMessage());
                return;
            }
            if (subOptionCode == CIRCUIT_ID_CODE) {
                agentCircuitId = new String(subOptionData);
            } else if (subOptionCode == REMOTE_ID_CODE) {
                agentRemoteId = new String(subOptionData);
            } else {
                log.debug("Unsupported subOption {} in DHCP option82 - {}",
                          subOptionCode, new String(subOptionData));
            }
        }
    }

    public void setAgentCircuitId(String value) {
        this.agentCircuitId = value;
    }

    public void setAgentCircuitId(byte[] subOptionData) {
        agentCircuitId = new String(subOptionData);
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
            buf.write(CIRCUIT_ID_CODE);
            buf.write((byte) agentCircuitId.length());
            byte[] bytes = agentCircuitId.getBytes(StandardCharsets.UTF_8);
            buf.write(bytes, 0, bytes.length);
        }

        // Add sub option if set
        if (agentRemoteId != null) {
            buf.write(REMOTE_ID_CODE);
            buf.write((byte) agentRemoteId.length());
            byte[] bytes = agentRemoteId.getBytes(StandardCharsets.UTF_8);
            buf.write(bytes, 0, bytes.length);
        }

        return buf.toByteArray();
    }

    @Override
    public String toString() {
        return "circuitId: " + agentCircuitId + " remoteId: " + agentRemoteId;
    }

}
