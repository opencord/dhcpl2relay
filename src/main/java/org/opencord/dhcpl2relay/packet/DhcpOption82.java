package org.opencord.dhcpl2relay.packet;

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

    public String getAgentCircuitId() {
        return this.agentCircuitId;
    }

    public void setAgentRemoteId(String value) {
        this.agentRemoteId = value;
    }

    public String getAgentRemoteId() {
        return this.agentRemoteId;
    }

    /**
     * Returns the length of the option 82.
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
     */
    public byte[] toByteArray() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        //buf.write((byte) 82); // option number
        //buf.write(length());

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