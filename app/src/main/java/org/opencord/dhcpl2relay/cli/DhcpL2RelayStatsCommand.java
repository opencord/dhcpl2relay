/*
 * Copyright 2017-2023 Open Networking Foundation (ONF) and the ONF Contributors
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

package org.opencord.dhcpl2relay.cli;


import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.opencord.dhcpl2relay.DhcpL2RelayEvent;
import org.opencord.dhcpl2relay.impl.DhcpL2RelayCounterNames;
import org.opencord.dhcpl2relay.impl.DhcpL2RelayCountersIdentifier;
import org.opencord.dhcpl2relay.impl.DhcpL2RelayCountersStore;

import java.util.Collections;
import java.util.Map;

/**
 * Display/Reset the DHCP L2 relay application statistics.
 */
@Service
@Command(scope = "onos", name = "dhcpl2relay-stats",
        description = "Display or Reset the DHCP L2 relay application statistics")
public class DhcpL2RelayStatsCommand extends AbstractShellCommand {
    private static final String CONFIRM_PHRASE = "please";

    @Option(name = "-r", aliases = "--reset", description = "Reset the counter[s]\n" +
            "(WARNING!!!: In case no counter name is explicitly specified, all DHCP L2 Relay counters will be reset).",
            required = false, multiValued = false)
    private boolean reset = false;

    @Option(name = "-s", aliases = "--subscriberId", description = "Subscriber Id\n",
            required = false, multiValued = false)
    private String subscriberId = null;

    @Option(name = "-p", aliases = "--please", description = "Confirmation phrase",
            required = false, multiValued = false)
    String please = null;

    @Argument(index = 0, name = "counter",
            description = "The counter to display (or reset). In case not specified, all counters\nwill be " +
                    "displayed (or reset in case the -r option is specified).",
            required = false, multiValued = false)
    DhcpL2RelayCounterNames counter = null;

    @Override
    protected void doExecute() {
        DhcpL2RelayCountersStore dhcpCounters = AbstractShellCommand.get(
                DhcpL2RelayCountersStore.class);

        if ((subscriberId == null) || (subscriberId.equals("global"))) {
            // All subscriber Ids
            subscriberId = DhcpL2RelayEvent.GLOBAL_COUNTER;
        }

        if (reset) {
            if (please == null || !please.equals(CONFIRM_PHRASE)) {
                print("WARNING: Be aware that you are going to reset the counters. " +
                        "Enter confirmation phrase to continue.");
                return;
            }
            if (counter == null) {
                // Reset all global counters
                dhcpCounters.resetCounters(subscriberId);
            } else {
                // Reset the specified counter
                dhcpCounters.setCounter(subscriberId, counter, (long) 0);
            }
        } else {
            Map<DhcpL2RelayCountersIdentifier, Long> countersMap = dhcpCounters.getCounters().counters();
            if (countersMap.size() > 0) {
                if (counter == null) {
                    String jsonString = "";
                    if (outputJson()) {
                        jsonString = String.format("{\"%s\":{", dhcpCounters.NAME);
                    } else {
                        print("%s [%s] :", dhcpCounters.NAME, subscriberId);
                    }
                    DhcpL2RelayCounterNames[] counters = DhcpL2RelayCounterNames.values();
                    for (int i = 0; i < counters.length; i++) {
                        DhcpL2RelayCounterNames counterType = counters[i];
                        Long value = countersMap.get(new DhcpL2RelayCountersIdentifier(subscriberId, counterType));
                        if (value == null) {
                            value = 0L;
                        }
                        if (outputJson()) {
                            jsonString += String.format("\"%s\":%d", counterType, value);
                            if (i < counters.length - 1) {
                                jsonString += ",";
                            }
                        } else {
                            printCounter(counterType, value);
                        }
                    }
                    if (outputJson()) {
                        jsonString += "}}";
                        print("%s", jsonString);
                    }
                } else {
                    // Show only the specified counter
                    Long value = countersMap.get(new DhcpL2RelayCountersIdentifier(subscriberId, counter));
                    if (value == null) {
                        value = 0L;
                    }
                    if (outputJson()) {
                        print("{\"%s\":%d}", counter, value);
                    } else {
                        printCounter(counter, value);
                    }
                }
            } else {
                print("No DHCP L2 Relay Counters were created yet for counter class [%s]",
                        DhcpL2RelayEvent.GLOBAL_COUNTER);
            }
        }
    }

    private void printCounter(DhcpL2RelayCounterNames counterNames, long value) {
        // print in non-JSON format
        print("  %s %s %-4d", counterNames,
                String.join("", Collections.nCopies(50 - counterNames.toString().length(), ".")), value);
    }
}