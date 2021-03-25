# Starter Code Overview

See [router requirements](router_requirements.md) for the details of the functionality your router must implement.

## Data-Plane Starter Code

The P4 data-plane starter code is in the `router.p4app/simple_router.p4` P4 file. It contains a very simple router design with a single table that simply matches on the packet's source port and either invokes an action called `set_output_port` or `NoAction` depending on the configured table entries. Obviously this not how an internet router works so your job is as follows:

* Define additional headers
* Extend parser to parse your additional headers
* Define additional tables and actions
* Implement match-action control-flow
* Extend deparser to emit your additional headers

The routing table for this project can either be implemented as a longest prefix match table (LPM) or a ternary match table. Because some hardware targets do not fully support LPM tables, we chose to implement the routing table with ternary match. In your implementation, you can choose whether to implement the routing table with LPM or ternary match. We have provided some wrapper functions in the control-plane starter code for you to try and expose LPM-like functionality on top of the ternary table. The main difference between the ternary match and LPM tables is that the control-plane must explicitly manage the priority of each entry. The priority is indicated by the entry's address, smaller addresses indicate higher priority. This should not be confused with the `priority` of [P4RT entries](https://p4.org/p4runtime/spec/v1.3.0/P4Runtime-Spec.html#sec-table-entry), where _larger_ `priority` values indicate higher priority.

The `digest_header` is a header that the router should prepend to all packets being forwarded to the local control-plane. Upon receiving a packet from the data-plane, the control-plane will first extract the digest information from the front of the packet. The starter code defines the `digest_header` as follows:

```
header digest_header_h {
    bit<8>   src_port;
    bit<8>   digest_code;
}
```

The starter code also defines the following digest codes so that the data-plane can tell the control-plane why it sent each packet to the control-plane:

```
typedef bit<8> digCode_t;
const digCode_t DIG_LOCAL_IP = 1;
const digCode_t DIG_ARP_MISS = 2;
const digCode_t DIG_ARP_REPLY = 3;
const digCode_t DIG_TTL_EXCEEDED = 4;
const digCode_t DIG_NO_ROUTE = 5;
```

## Control-Plane Starter Code

The control-plane starter code is in the `router.p4app/control_plane/` directory.

You will want to implement `handle_pkt` in `control_plane.py`, as well as implement `arp_cache.py` and, after you have confirmed that static routing works properly, `PWOSPF_handler.py`. You will also need to update some values in `control_plane/utils/consts.py` (all marked with `TODO`) and implement `Tables_populator` in `tables.py`.

`test/test_network.py`, `test/baseline_test.py`, and `parse_config_file` in `control_plane/config.py`, assume that your routing table action params are `{port: <egress port>, next: <next hop ip>}`, e.g.;
```
    action ipv4_forward(port_t port, IPv4Addr_t next) {
```

There are `TODO`s that indicate which code to change if you choose to have different action data for your routing table.

The `router.p4app/topos/` directory contains a few configuration topologies that you might want to use to when testing.

# Testing

`router.p4app` contains multiple entry points in `router.p4app/main/`:

 - `single.py`: setup a topology with a single switch and two hosts.
 - `triangle.py`: setup a triangle topology and send packets between hosts connected to different switches.
 - `baseline_test.py`: test the switch without the control plane.
 - `control_plane_test.py`: test the control plane alone, without running the switch.

To choose a p4app entry point, create a symbolic link from `main.py` to one of the above. For example, to run the `single.py` entry point:
```
cd router.p4app/
ln -fs main/single.py main.py
~/src/p4app/p4app run .
```

## Baseline Tests

The baseline tests use the test network defined in `test/test_network.py`.

### Data-Plane Baseline Tests

The data-plane baseline tests are located in the `router.p4app/test/baseline_test.py` script. This file populates the switch tables with the topology shown below, and sends packets to a single switch (self - rid: 10.6.0.3). Each test is defined by an input packet + metadata and an expected output packet + metadata. See the script for a short description of the functionality that each test is intended to exercise.

To run the test, use the `main/baseline_test.py` p4app entry point:
```
cd router.p4app/
ln -fs main/baseline_test.py main.py
~/src/p4app/p4app run .
```

In order to run the tests, you must have implemented `Tables_populator` in `control_plane/tables.py`.

Alternately, you may manually populate the tables with `sw.insertTableEntry(...)` to reflect the following topology:
```
               ##################
               eh0 - ip: 10.6.3.2
               ##################
                       |
                       |
                iface3:10.6.3.3   iface2:
             #################### 10.6.2.3        ##################
             self - rid: 10.6.0.3 --------------- r2 - rid: 10.2.0.3
             ####################        10.6.2.2 ##################
     iface1:10.6.1.3     iface0:10.6.0.3      10.2.0.3
            /                     \               /
           /                       \             /
     10.6.1.2                    10.6.0.2    10.2.0.2
##################                ##################
r1 - rid: 10.1.0.3                r0 - rid: 10.0.0.3
##################                ##################
       10.1.0.3                  10.0.0.3
           \                       /
            \                     /
           10.1.0.2          10.0.0.2
               ##################
               r3 - rid: 10.3.0.3
               ##################
```
You must also have a routing entry for `50.64.3.7` that does not have a corresponding arp cache entry.

### Control-Plane Baseline Tests

The control-plane baseline tests are located in `router.p4app/test/control_plane/sanity_check.py`.

It is possible that, although a new control plane is instantiated for each test, your state will not be fully cleared before the start of each test. If you encounter this issue, simply clear state in `setUp`.

To run the control plane tests, change the p4app entry point:
```
cd router.p4app/
ln -fs main/control_plane_test.py main.py
~/src/p4app/p4app run .
```

This will run tests for both static routing and PWOSPF. To run just the baseline tests for static routing, run `p4app run . Baseline_tests`. The `TIMEOUT_TESTS` boolean can be set to `False` in order to skip tests that take a particularly long time to run.

### Mininet

You can try running standard Mininet commands in the Mininet console to test your router. For example:
* ping between hosts (ex: `h1 ping h2`)
* ping router interfaces
* traceroute to and through routers
* iperf through routers
* breaking a link and ensuring that the routers recover the correct forwarding state
    * `mininet> link s1 s2 down`

# Hints and Tips

* Take a look at some [general p4app debugging tips](https://2021-cs344.github.io/documentation/debugging-p4app/).
* Are you handling PWOSPF HELLO packets correctly in the data-plane? What IP address are they sent to?
* Be sure to make use of the P4RT commands (e.g., `insertTableEntry()`, `printTableEntries()`) to add/inspect table entries.
* Possible initial tests:
    * Is your router forwarding correctly with statically configured table entries?
    * Can you ping each of the routers interfaces?
    * Is the router responding to ARP requests?
    * Be careful if you are trying to ping one interface from the other. Unless you are careful, linux will force the traffic to use the loopback interface rather than sending packets out onto the wire. [It is possible](https://serverfault.com/questions/127636/force-local-ip-traffic-to-an-external-interface) to do this, but it'll be easier (and less confusing) if you can arrange a time with a neighboring group to use their NIC. Then you can do small tests like sending pings through the router, traceroute to and through the router, send iperf flows through the router, and so on.
* Inspect the Mininet network by [launching the Mininet console from the p4app entry point](https://github.com/2021-cs344/p4app/blob/rc-2.0.0/examples/wire.p4app/main.py#L13), e.g.,
    * `mininet> h1 ifconfig`
* Configure interface with IP address:
    * `# ifconfig eth1 1.2.3.4 netmask 255.255.255.0`
* Configure interface with MAC address:
    * `# ifconfig eth1 hw ether 00:11:22:33:44:55`
* Adding routing table entries on Ubuntu:
    * `# route add -net 1.1.1.0 netmask 255.255.255.0 gw 12.12.12.13 dev eth2`
* Show routing table entries:
    * `# route -n`
* Show the route to a host:
    * `# ip route get 12.12.12.12`
* Show arp table entries:
    * `# arp -i eth1`
* If the `eth1` or `eth2` interfaces are down then you probably just need to configure them with an IP address using the `ifconfig` command as shown above.
