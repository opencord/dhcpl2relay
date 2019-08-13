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

import java.util.Objects;

public class DhcpL2RelayCountersIdentifier {
    final String counterClassKey;
    final String counterTypeKey;

    public DhcpL2RelayCountersIdentifier(String counterClassKey, String counterTypeKey) {
        this.counterClassKey = counterClassKey;
        this.counterTypeKey = counterTypeKey;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof DhcpL2RelayCountersIdentifier) {
            final DhcpL2RelayCountersIdentifier other = (DhcpL2RelayCountersIdentifier) obj;
            return Objects.equals(this.counterClassKey, other.counterClassKey)
                    && Objects.equals(this.counterTypeKey, other.counterTypeKey);
        }

        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hash(counterClassKey, counterTypeKey);
    }
}