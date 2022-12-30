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
from threading import Thread, Event

from control_plane.arp_cache import ARP_cache
from control_plane.headers.PWOSPF_headers import PWOSPF
from control_plane.headers.digest_header import Digest_data
from control_plane.PWOSPF_handler import PWOSPF_handler
from control_plane.utils.consts import *
from control_plane.async_sniff import sniff

VALID_DIG_CODES = [DIG_ARP_REPLY, DIG_ARP_MISS, DIG_LOCAL_IP, \
    DIG_TTL_EXCEEDED, DIG_NO_ROUTE]
VALID_ETHERTYPES = [0x0806, 0x0800] # ARP and IP

"""
The control plane is the entry point for handling packets that are sent from the
data plane. Its responsibilities include populating the ARP cache, managing the
routing table, and generating ICMP error packets.
"""
class Control_plane(Thread):
    """
    Initializes the control plane

    @param config a Config object that contains information needed to run the
                  control plane
    """
    def __init__(self, config):
        super(Control_plane, self).__init__()
        self.stop_event = Event()
        self.start_wait = 0.3 # time to wait for the controller to be sniffing
        self.tables_api = config.tables_api
        self.sendp = config.sendp
        self.ifaces = config.ifaces
        self.sniff_iface = config.dma_iface
        self.rtable = config.rtable
        self.arp_cache = ARP_cache(config)
        self.pwospf_handler = PWOSPF_handler(config) \
            if config.pwospf_enabled else None

    """
    Calls handle_pkt on all packets sent to the control plane's interface. This
    method blocks indefinitely.
    """
    def run(self):
        sniff(iface=self.sniff_iface, prn=self.handle_pkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(Control_plane, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(Control_plane, self).join(*args, **kwargs)

    """
    Determines if a received packet is legitimate

    @return True if the packet has a valid digest code and ethertype
    """
    def pkt_valid(self, pkt):
        return pkt[Digest_data].digest_code in VALID_DIG_CODES and \
            pkt[Ether].type in VALID_ETHERTYPES


    """
    Performs operations based on the opcode in the Digest_data header of a
    packet

    @param pkt the packet to process
    """
    def handle_pkt(self, pkt):
        pkt = Digest_data(bytes(pkt))
        if not self.pkt_valid(pkt): return

        # pkt is a Scapy packet with the format:
        #   Digest_data() / Ether() / ... payload ...
        # TODO: handle the packet appropriately
        DIG_CODE = pkt[Digest_data].digest_code
        if (DIG_CODE == DIG_LOCAL_IP):
            # send the packet
            self.sendp(pkt)
            return
        
        elif (DIG_CODE == DIG_NO_ROUTE):
            # find route 
            return
        
        elif (DIG_CODE == DIG_TTL_EXCEEDED):
            # drop packet 
            return
        
        elif(DIG_CODE == DIG_ARP_MISS):
            # no ARP match found for IP packet 
            return

        elif(DIG_CODE == DIG_ARP_REPLY):
            # reply ARP request by looking into ARP cache
            return

        else: 
            return
        # ***** HANDLE ARP / POPULATING ARP CACHE ***** #
        if pkt[Ether].type == 0x0806:
            if pkt[ARP].op
