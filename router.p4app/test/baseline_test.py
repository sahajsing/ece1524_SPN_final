#!/usr/bin/env python

#
# Copyright (c) 2017 Stephen Ibanez, 2021 Theo Jepsen
# All rights reserved.
#
# This software was developed by Stanford University and the University of Cambridge Computer Laboratory
# under National Science Foundation under Grant No. CNS-0855268,
# the University of Cambridge Computer Laboratory under EPSRC INTERNET Project EP/H040536/1 and
# by the University of Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249 ("MRC2"),
# as part of the DARPA MRC research programme.
#

import time
from scapy.all import Ether, IP, ARP, TCP, sendp
from threading import Thread, Event
from control_plane.utils.consts import nf_port_map, DIG_ARP_MISS, DIG_ARP_REPLY, RTABLE_ACTION_NAME
from control_plane.headers.digest_header import Digest_data
from control_plane.headers.PWOSPF_headers import PWOSPF
from control_plane.tables import Bmv2_grpc_tables_api, Tables_populator
from control_plane.async_sniff import sniff
from test.test_network import Test_network

TEST_TTL = 53
CPU_PORT = 1

class PortTester():
    def __init__(self, ifaces, timeout=2):
        self.ifaces = ifaces
        self.ports = list(range(1, len(ifaces)+1))
        self.sniff_threads = []
        self.stop_event = Event()
        self.start_wait = 0.3 # time to wait for the controller to be sniffing
        self.pkts_for_port = {p: [] for p in self.ports}
        self.event_for_port = {p: Event() for p in self.ports}
        self.port_for_iface = {i: p for i,p in zip(self.ifaces, self.ports)}
        self.iface_for_port = {p: i for i,p in self.port_for_iface.items()}
        self.last_sent = None
        self.last_sent_port = None
        self.timeout = timeout

    def wasSentByMe(self, port, pkt):
        if self.last_sent_port is not None and self.last_sent_port == port:
            assert str(self.last_sent)[:20] == str(pkt)[:20]
            self.last_sent_port = None
            return True
        return False
        #pkt1 = self.last_sent
        #if pkt1[Ether].src != pkt[Ether].src or pkt1[Ether].dst != pkt[Ether].dst or pkt1[Ether].type != pkt[Ether].type: return False
        #if IP in pkt:
        #    if pkt1[IP].ttl != pkt[IP].ttl or pkt1[IP].src != pkt[IP].src or pkt1[IP].dst != pkt[IP].dst:
        #        return False
        #return True

    def sniffThread(self, port):
        def handlePkt(pkt):
            if port == self.ports[0]: # CPU port
                pkt = Digest_data(bytes(pkt))
            #print(port, "received:")
            #pkt.show2()
            if self.wasSentByMe(port, pkt): return
            self.pkts_for_port[port].append(pkt)
            self.event_for_port[port].set()
        sniff(iface=self.iface_for_port[port], prn=handlePkt, stop_event=self.stop_event)

    def newPkts(self):
        new = {}
        for port,pkts in self.pkts_for_port.items():
            if len(pkts): new[port] = pkts
            self.pkts_for_port[port] = []
        return new

    def start(self, *args, **kwargs):
        for port in self.ports:
            t = Thread(target=self.sniffThread, args=(port,))
            t.start()
            self.sniff_threads.append(t)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        for t in self.sniff_threads:
            t.join()

    def sendPkt(self, inPort, pkt, expPort, expPkt):
        if expPort is not None:
            self.event_for_port[expPort].clear()
        self.sendp(inPort, pkt, verbose=0)
        if expPort is not None:
            self.event_for_port[expPort].wait(self.timeout)
            out = self.newPkts()
            assert len(out) == 1, "expecting a single packet on port %d, but got %d: %s" % (expPort, len(out), out)
            assert expPort in out, "expecting packet on port %d, but got: %s" % (expPort, out)
            assert len(out[expPort]) == 1, "expecting a single packet on port %d, but got %d: %s" % (expPort, len(out), out)
            outPkt = out[expPort][0]
            assert str(outPkt) == str(expPkt)
        else:
            time.sleep(self.timeout)
            out = self.newPkts()
            assert len(out) == 0, "not expecting any packets, but got: %s" % out

    def sendp(self, inPort, pkt, *args, **kwargs):
        kwargs['iface'] = self.iface_for_port[inPort]
        self.last_sent = pkt
        self.last_sent_port = inPort
        sendp(pkt, *args, **kwargs)


def pop_tables(sw, tables_api):
    network = Test_network()

    ifaces = network.rself.ifaces

    # add an entry to the arp cache for each neighbor
    arp_cache_entries = []
    for i in network.rself.ifaces:
        niface = network.rself.niface(i.ip)
        arp_cache_entries.append((niface.ip, niface.mac))

    # routing table should contain an additional entry for 50.64.3.7 that does
    # not have a corresponding arp cache entry
    rtable = network.rtable.copy()
    rtable.append('50.64.3.7', 32, (RTABLE_ACTION_NAME,
        # TODO: update if your data-plane routing table input parameters
        #       are not [dst_port, next_hop_ip]
        [ifaces[2].port, '0.0.0.0']))

    populator = Tables_populator(tables_api)
    populator.load_rtable(rtable)
    populator.load_ifaces(ifaces)
    populator.load_arp_cache(arp_cache_entries)


def run_test(sw):
    NETWORK = Test_network()
    IFACES = NETWORK.rself.ifaces
    HOSTS = [NETWORK.rself.niface(i.ip) for i in IFACES[:3]]
    HOSTS.append(NETWORK.r3.ifaces[0])

    tables_api = Bmv2_grpc_tables_api(sw)
    pop_tables(sw, tables_api)

    try:
        #cp.start()
        ifaces = [sw.intfs[i].name for i in sorted(sw.intfs.keys()) if i > 0]
        pt = PortTester(ifaces)
        pt.start()


        ip_hdr = Ether(dst=IFACES[0].mac, src=HOSTS[0].mac) / \
            IP(dst=HOSTS[1].ip, src=HOSTS[0].ip, ttl=TEST_TTL)
        tcp_pkt = ip_hdr.copy() / TCP() / 'TEST PAYLOAD OF PKT'

        # BASELINE TESTS #

        # 1. Test IP/TCP forwarding, one hop
        ingress_pkt = tcp_pkt.copy()
        egress_pkt = ingress_pkt.copy()
        egress_pkt[Ether].dst = HOSTS[1].mac
        egress_pkt[Ether].src = IFACES[1].mac
        egress_pkt[IP].ttl -= 1 # checksum computed automatically with scapy
        pt.sendPkt(nf_port_map['nf0'], ingress_pkt, IFACES[1].port, egress_pkt)
        print(".", end='', flush=True)

        # 2. Test IP/TCP forwarding, multiple hops
        ingress_pkt = tcp_pkt.copy()
        ingress_pkt[IP].dst = HOSTS[3].ip
        egress_pkt = ingress_pkt.copy()
        egress_pkt[Ether].dst = HOSTS[0].mac
        egress_pkt[Ether].src = IFACES[0].mac
        egress_pkt[IP].ttl -= 1 # checksum computed automatically with scapy
        pt.sendPkt(nf_port_map['nf0'], ingress_pkt, IFACES[0].port, egress_pkt)
        print(".", end='', flush=True)

        # 3. Test IP packet with bad checksum
        pkt = tcp_pkt.copy()
        pkt[IP].chksum = 314
        # pkt should be dropped
        pt.sendPkt(nf_port_map['nf0'], pkt, None, None)
        print(".", end='', flush=True)

        # 4. Test IP destination not in arp cache
        ingress_pkt = tcp_pkt.copy()
        ingress_pkt[IP].dst = '50.64.3.7'
        # Note: our implementation updates the source mac during LPM
        # routing, but it would also be valid to update it only after
        # a destination mac is found
        egress_pkt = ingress_pkt.copy()
        egress_pkt[Ether].src = IFACES[2].mac
        # should be forwarded to control plane
        egress_pkt = Digest_data(src_port=nf_port_map['nf0'],
          digest_code=DIG_ARP_MISS) / egress_pkt
        pt.sendPkt(nf_port_map['nf0'], ingress_pkt, CPU_PORT, egress_pkt)
        print(".", end='', flush=True)

        # 5. Test packet from control plane
        ingress_pkt = tcp_pkt.copy()
        egress_pkt = ingress_pkt.copy()
        egress_pkt[Ether].dst = HOSTS[1].mac
        egress_pkt[Ether].src = IFACES[1].mac
        egress_pkt[IP].ttl -= 1 # checksum computed automatically with scapy
        pt.sendPkt(CPU_PORT, ingress_pkt, IFACES[1].port, egress_pkt)
        print(".", end='', flush=True)

        # 6. Test ARP reply destined to router
        ingress_pkt = Ether(dst=IFACES[1].mac, src=HOSTS[1].mac) / \
            ARP(op='is-at', hwdst=IFACES[1].mac, hwsrc=HOSTS[1].mac,
                pdst=IFACES[1].ip, psrc=HOSTS[1].ip)
        # should be forwarded to control plane
        egress_pkt = Digest_data(src_port=nf_port_map['nf1'], digest_code=DIG_ARP_REPLY) / ingress_pkt.copy()
        pt.sendPkt(nf_port_map['nf1'], ingress_pkt, CPU_PORT, egress_pkt)
        print(".", end='', flush=True)

        # 7. Test unsupported Ethernet protocol (AppleTalk)
        ingress_pkt = Ether(dst=IFACES[0].mac, src=HOSTS[0].mac, type=0x809B)
        # pkt should be dropped
        pt.sendPkt(nf_port_map['nf0'], ingress_pkt, None, None)
        print(".", end='', flush=True)

        # TODO: Add more test cases below ...

        print("\nOK")

    finally:
        pt.join()
