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


import org.apache.karaf.shell.commands.Argument;
import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.onosproject.cli.AbstractShellCommand;

import java.util.Collections;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Display/Reset the DHCP L2 relay application statistics.
 */
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
    DhcpL2RelayCounters counter = null;

    @Override
    protected void execute() {
        DhcpL2RelayCountersStore dhcpCounters = AbstractShellCommand.get(
                DhcpL2RelayCountersStore.class);

        if ((subscriberId == null) || (subscriberId.equals("global"))) {
            // All subscriber Ids
            subscriberId = DhcpL2RelayCountersIdentifier.GLOBAL_COUNTER;
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
           Map<DhcpL2RelayCountersIdentifier, AtomicLong> countersMap = dhcpCounters.getCountersMap();
           if (countersMap.size() > 0) {
               if (counter == null) {
                   String jsonString = "";
                   if (outputJson()) {
                       jsonString = String.format("{\"%s\":{", dhcpCounters.NAME);
                   } else {
                       print("%s [%s] :", dhcpCounters.NAME, subscriberId);
                   }
                   for (Iterator<DhcpL2RelayCounters> it = DhcpL2RelayCounters.SUPPORTED_COUNTERS.iterator();
                        it.hasNext();) {
                       DhcpL2RelayCounters counterType = it.next();
                       AtomicLong v = countersMap.get(new DhcpL2RelayCountersIdentifier(subscriberId, counterType));
                       if (v == null) {
                           v = new AtomicLong(0);
                       }
                       if (outputJson()) {
                           jsonString += String.format("\"%s\":%d", counterType, v.longValue());
                           if (it.hasNext()) {
                               jsonString += ",";
                           }
                       } else {
                           printCounter(counterType, v);
                       }
                   }
                   if (outputJson()) {
                       jsonString += "}}";
                       print("%s", jsonString);
                   }
               } else {
                   // Show only the specified counter
                   AtomicLong v = countersMap.get(new DhcpL2RelayCountersIdentifier(subscriberId, counter));
                   if (v == null) {
                       v = new AtomicLong(0);
                   }
                   if (outputJson()) {
                       print("{\"%s\":%d}", counter, v.longValue());
                   } else {
                       printCounter(counter, v);
                   }
               }
           } else {
               print("No DHCP L2 Relay Counters were created yet for counter class [%s]",
                       DhcpL2RelayCountersIdentifier.GLOBAL_COUNTER);
           }
       }
    }

    void printCounter(DhcpL2RelayCounters c, AtomicLong a) {
        // print in non-JSON format
        print("  %s %s %-4d", c,
                String.join("", Collections.nCopies(50 - c.toString().length(), ".")),
                a.longValue());
    }
}