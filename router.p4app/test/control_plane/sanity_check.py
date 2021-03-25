#!/usr/bin/env python

#
# Copyright (c) 2018 Sarah Tollman, 2021 Theo Jepsen
# All rights reserved.
#
# This software was developed by Stanford University and the University of Cambridge Computer Laboratory
# under National Science Foundation under Grant No. CNS-0855268,
# the University of Cambridge Computer Laboratory under EPSRC INTERNET Project EP/H040536/1 and
# by the University of Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249 ("MRC2"),
# as part of the DARPA MRC research programme.
#

from scapy.all import *
import unittest

from control_plane.arp_cache import NUM_ARP_ATTEMPTS
from control_plane.config import Config
from control_plane.control_plane import Control_plane
from control_plane.headers.PWOSPF_headers import *
from control_plane.headers.digest_header import Digest_data
from test.control_plane.sim_tables_api import Sim_tables_api
from test.test_network import Test_network
from control_plane.utils.addr_conversions import *
from control_plane.utils.consts import *
from control_plane.utils.LPM_dict import LPM_dict

"""
This file provides a set of baseline tests for the functionality of
your control plane, both with and without PWOSPF enabled. These tests
are not comprehensive, and you are encouraged to add your own.

(Our implemenation allows timeouts to be configurable so that timeout tests
can run faster.)

Note: you may run into the issue that python unittest does not properly
clear the state of your control plane before each test, even though you
are instantiating a new control plane in setUp. (In particular, you may
encounter this if you use default initializers at any point.) To fix this,
simply clear the state of the variable in setUp.
For example: self.cp.custom_class.variable = []
"""

class Mock_sender():
    def __init__(self):
        self.pkts = []

    def sendp(self, pkt):
        self.pkts.append(pkt)

NETWORK = Test_network()
IFACE0 = NETWORK.rself.ifaces[0]
NIFACE0 = NETWORK.rself.niface(IFACE0.ip)
IFACE1 = NETWORK.rself.ifaces[1]
NIFACE1 = NETWORK.rself.niface(IFACE1.ip)
IFACE2 = NETWORK.rself.ifaces[2]
NIFACE2 = NETWORK.rself.niface(IFACE2.ip)

DST_IP_TO_SRC_MAC = {
    NIFACE0.ip: IFACE0.mac,
    NIFACE1.ip: IFACE1.mac,
    NIFACE2.ip: IFACE2.mac
}

ARP_REPLY_PKT = Digest_data(digest_code=DIG_ARP_REPLY) / \
    Ether(dst=IFACE0.mac, src=NIFACE0.mac) / \
    ARP(op='is-at', pdst=IFACE0.ip, psrc=NIFACE0.ip,
        hwdst=NIFACE0.mac, hwsrc=IFACE0.mac)

ARP_MISS_PKT = Digest_data(digest_code=DIG_ARP_MISS) / \
    Ether(dst=IFACE1.mac, src=NIFACE1.mac) / \
    IP(dst=NIFACE0.ip, src=NIFACE1.ip)

HELLO_PKT = Digest_data(digest_code=DIG_LOCAL_IP, src_port=NIFACE2.port) / \
    Ether(dst=IFACE2.mac, src=NIFACE2.mac) / \
    IP(dst=ALLSPFRouters, src=NIFACE2.ip) / \
    PWOSPF(rid=NETWORK.r2.rid) / HELLO(mask=IFACE2.mask, helloint=int(HELLOINT))

LSU_PKT = Digest_data(digest_code=DIG_LOCAL_IP, src_port=IFACE0.port) / \
    Ether(dst=IFACE0.mac, src=NIFACE0.mac) / \
    IP(dst=IFACE0.ip, src=NIFACE0.ip) / \
    PWOSPF(rid=NETWORK.r0.rid) / LSU(seqno=1, ads=[])

# Set this to False if you would like to skip the tests that test entry timeouts
# (this will allow the overall test suite to complete faster)
TIMEOUT_TESTS = True

class Baseline_tests(unittest.TestCase):
    # instantiate control plane before each test
    def setUp(self):
        self.msender = Mock_sender()
        self.tables_api = Sim_tables_api()
        config = Config(
            tables_api=self.tables_api,
            sendp=self.msender.sendp,
            ifaces=NETWORK.rself.ifaces,
            rtable=NETWORK.rtable.copy(),
            pwospf_enabled=False
        )
        self.cp = Control_plane(config)

    # asserts that the pkt is ICMP, with the provided type and code,
    # and that the address fields are correct given the source packet
    def assertICMP(self, src_pkt, icmp_pkt, icmp_type, icmp_code):
        self.assertIn(ICMP, icmp_pkt)
        self.assertEqual(icmp_pkt[ICMP].type, icmp_type)
        self.assertEqual(icmp_pkt[ICMP].code, icmp_code)
        self.assertIn(IP, icmp_pkt)
        self.assertEqual(icmp_pkt[IP].dst, src_pkt[IP].src)
        self.assertIn(Ether, icmp_pkt)
        self.assertEqual(icmp_pkt[Ether].src,
            DST_IP_TO_SRC_MAC[icmp_pkt[IP].dst])

    # test that an arp request is sent to the next-hop ip address
    # when there is an arp cache miss in the data plane
    def test_arp_miss(self):
        pkt = ARP_MISS_PKT.copy()
        self.cp.handle_pkt(pkt)

        self.assertEqual(len(self.msender.pkts), 1)
        p = self.msender.pkts[0]
        self.assertIn(ARP, p)
        self.assertEqual(p[ARP].op, 1) # who-has
        self.assertEqual(p[ARP].hwdst, ETH_BROADCAST)
        self.assertEqual(p[ARP].pdst, NIFACE0.ip)
        self.assertEqual(p[Ether].dst, ETH_BROADCAST)

    # test that when a packet is sent to the control plane because there
    # was an arp miss, the cp sends a maximum number of arp requests
    # before sending a host unreachable to the source
    @unittest.skipUnless(TIMEOUT_TESTS, 'Timeout tests disabled')
    def test_arp_miss_sends_five_arp_reqs_then_icmp(self):

        # send two ARP cache miss packets to the control plane
        # for different destination IP but same next-hop IP
        pkt1 = ARP_MISS_PKT.copy()
        pkt1[IP].dst = NETWORK.r0.ifaces[2].ip
        self.cp.handle_pkt(pkt1)
        pkt2 = ARP_MISS_PKT.copy()
        self.cp.handle_pkt(pkt2)
        pkts = [pkt1, pkt2]

        # snooze to let the control plane's ARP requests time out
        for i in range(NUM_ARP_ATTEMPTS + 3): # allow for small buffer
            time.sleep(1)

        # verify that the CP has sent two packets in addition to
        # the maximum number of arp packets
        self.assertEqual(len(self.msender.pkts), NUM_ARP_ATTEMPTS + 2)

        # assert that the maximum number of ARP requests were sent
        for p in self.msender.pkts[:-2]:
            self.assertIn(ARP, p)
            self.assertEqual(p[ARP].op, 1) # who-has
            self.assertEqual(p[ARP].hwdst, ETH_BROADCAST)
            self.assertEqual(p[ARP].pdst, NIFACE0.ip)
            self.assertEqual(p[Ether].dst, ETH_BROADCAST)

        # assert that after ARP fails ICMP host unreachable is sent
        # for all enqueued packets
        for p in self.msender.pkts[-2:]:
            src_pkt = list(filter(lambda src_p: p[IP].dst == src_p[IP].src, pkts))[0]
            pkts.remove(src_pkt)
            self.assertICMP(src_pkt, p, ICMP_UNREACH_TYPE,
                ICMP_HOST_UNREACH_CODE)

    # verify that the control plane adds an entry to the arp cache
    # table when it receives an arp reply
    def test_arp_reply_populates_arp_cache(self):
        pkt = ARP_REPLY_PKT.copy()

        self.cp.handle_pkt(pkt)

        result = self.tables_api.table_cam_read_entry(ARP_CACHE_TABLE_NAME,
            [pkt[Ether].psrc])
        # result format will be ('True'/'False', action, [action_params])
        self.assertEqual(result[0], 'True')
        """
        TODO: check that the values of the entry are correct depending on the
        format of your table
        """

    # verify that stale cache entries are removed after the specified timeout
    @unittest.skipUnless(TIMEOUT_TESTS, 'Timeout tests disabled')
    def test_arp_cache_timeout(self):
        pkt = ARP_REPLY_PKT.copy()

        # add to arp cache
        self.cp.handle_pkt(pkt)
        result = self.tables_api.table_cam_read_entry(ARP_CACHE_TABLE_NAME,
            [pkt[Ether].psrc])
        self.assertEqual(result[0], 'True') # prior test checks correct values

        # sleep for cache timeout + small buffer
        # check that entry is removed
        time.sleep(CACHE_TIMEOUT + 1)
        result = self.tables_api.table_cam_read_entry(ARP_CACHE_TABLE_NAME,
            [pkt[Ether].psrc])
        self.assertEqual(result[0], 'False')

class PWOSPF_tests(unittest.TestCase):
    # instantiate control plane before each test
    def setUp(self):
        self.rtable = LPM_dict()
        self.msender = Mock_sender()
        self.tables_api = Sim_tables_api()
        config = Config(
            tables_api=self.tables_api,
            sendp=self.msender.sendp,
            ifaces=NETWORK.rself.ifaces,
            rtable=self.rtable,
            pwospf_enabled=True
        )
        self.cp = Control_plane(config)
        self.cp.pwospf_handler.topology_database.routers = []
        self.cp.pwospf_handler.topology_database.neighbors = \
            defaultdict(lambda: dict())

    # test that received LSU packets are forwarded to known neighbors
    def test_lsu_received(self):
        self.cp.handle_pkt(HELLO_PKT) # add neighbor
        self.cp.handle_pkt(LSU_PKT)

        # forward packet to neighbors
        pkts = list(filter(lambda p: p[PWOSPF].rid != NETWORK.rself.rid,
            self.msender.pkts))
        self.assertEqual(len(pkts), 1) # currently one neighbor
        self.assertIn(Ether, pkts[0])
        self.assertEqual(pkts[0][Ether].src, IFACE2.mac)
        self.assertIn(IP, pkts[0])
        self.assertEqual(pkts[0][IP].src, IFACE2.ip)
        self.assertEqual(pkts[0][IP].dst, NIFACE2.ip)
        pwospf = LSU_PKT[PWOSPF].copy()
        pwospf[LSU].ttl = DEFAULT_TTL - 1
        self.assertEqual(str(pkts[0][PWOSPF]), str(pwospf))

    # test that interface links bidirectional LSU advertisements
    # populate the routing table
    def test_routing_table(self):
        lsu_pkt1 = LSU_PKT.copy()
        lsu_pkt1[Ether].src = HELLO_PKT[Ether].src
        lsu_pkt1[IP].src = HELLO_PKT[IP].src
        lsu_pkt1[PWOSPF].rid = NETWORK.r2.rid
        subnet = NETWORK.r0.ifaces[1].subnet_str()
        lsu_pkt1[LSU].ads = [Advertisement(subnet=subnet,
            mask=NETWORK.r0.ifaces[1].mask, rid=NETWORK.r0.rid)]
        lsu_pkt2 = LSU_PKT.copy()
        lsu_pkt2[LSU].ads = [Advertisement(subnet=subnet,
            mask=NETWORK.r0.ifaces[1].mask, rid=NETWORK.r2.rid)]

        self.cp.handle_pkt(HELLO_PKT)
        self.cp.handle_pkt(lsu_pkt1)
        self.cp.handle_pkt(lsu_pkt2)

        # should have entries for each interface + the advertised link
        self.assertEqual(len(self.rtable.entries),
            len(NETWORK.rself.ifaces) + 1)
        """
        TODO: you may want to test that the values of the routing table are
        correct based on the format of your table.
        """

    # test that routing entries are removed after timeout
    @unittest.skipUnless(TIMEOUT_TESTS, 'Timeout tests disabled')
    def test_routing_table_timeout(self):
        lsu_pkt1 = LSU_PKT.copy()
        lsu_pkt1[Ether].src = HELLO_PKT[Ether].src
        lsu_pkt1[IP].src = HELLO_PKT[IP].src
        lsu_pkt1[PWOSPF].rid = NETWORK.r2.rid
        subnet = NETWORK.r0.ifaces[1].subnet_str()
        lsu_pkt1[LSU].ads = [Advertisement(subnet=subnet,
            mask=NETWORK.r0.ifaces[1].mask, rid=NETWORK.r0.rid)]
        lsu_pkt2 = LSU_PKT.copy()
        lsu_pkt2[LSU].ads = [Advertisement(subnet=subnet,
            mask=NETWORK.r0.ifaces[1].mask, rid=NETWORK.r2.rid)]

        self.cp.handle_pkt(HELLO_PKT)
        self.cp.handle_pkt(lsu_pkt1)
        self.cp.handle_pkt(lsu_pkt2)

        self.assertEqual(len(self.rtable.entries),
            len(NETWORK.rself.ifaces) + 1)

        time.sleep(3 * LSUINT + 1)

        self.assertEqual(len(self.rtable.entries),
            len(NETWORK.rself.ifaces))

    # test that HELLO packets are sent out of all interfaces
    # when the control plane is initialized
    def test_hello_sent(self):
        time.sleep(1) # allow small buffer for packet sending

        pkts = list(filter(lambda pkt: HELLO in pkt, self.msender.pkts))
        self.assertEqual(len(pkts), len(NETWORK.rself.ifaces))
        remaining_ifaces = { i.mac: i for i in NETWORK.rself.ifaces }

        # assert that a packet is sent from each interface
        for pkt in pkts:
            self.assertIn(Ether, pkt)
            self.assertEqual(pkt[Ether].dst, ETH_BROADCAST)

            iface = remaining_ifaces.get(pkt[Ether].src)
            self.assertIsNotNone(iface)
            del remaining_ifaces[pkt[Ether].src]

            self.assertIn(IP, pkt)
            self.assertEqual(pkt[IP].src, iface.ip)
            self.assertEqual(pkt[IP].dst, ALLSPFRouters)

            self.assertIn(PWOSPF, pkt)
            self.assertEqual(pkt[PWOSPF].version, 2)
            self.assertEqual(pkt[PWOSPF].type, PWOSPF_HELLO_TYPE)
            self.assertEqual(pkt[PWOSPF].rid, IFACE0.ip)
            self.assertEqual(pkt[PWOSPF].aid, ALLSPFRouters)

            self.assertIn(HELLO, pkt)
            self.assertEqual(pkt[HELLO].mask, iface.mask)
            self.assertEqual(pkt[HELLO].helloint, HELLOINT)

if __name__ == '__main__':
    unittest.main()
