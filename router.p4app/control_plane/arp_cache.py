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

from collections import namedtuple
from datetime import datetime, timedelta
from scapy.all import *
from threading import Thread, Lock

from control_plane.utils.consts import *

NUM_ARP_ATTEMPTS = 5

"""
The ARP cache is responsible for managing ARP requests, populating the arp cache
table, and timing out expired cache entries
"""
class ARP_cache():

    """
    Initializes the ARP cache

    @param config a Config object
    """
    def __init__(self, config):
        self.tables_api = config.tables_api # used to populate ARP cache
        self.ifaces = config.ifaces # interfaces - port, ip, mask, mac
        self.sendp = config.sendp # sends packet
        self.rtable = config.rtable # routing table

        # TODO: initialize ARP handling thread(s)?
    def initialize_thread(self):
        self.initialize_thread
        # TODO: define additional helper methods
        # One possible approach for handling the ARP cache is to define two
        # additional threads:
        # 1. To send multiple arp requests per destination ip address before
        #    sending and ICMP host unreachable if none of the requests receive
        #    a response
        # 2. To remove stale cache entries
    
    def check_ARP_Cache(self, ip, mac):
        # first check if MAC address is in the ARP Cache table - no duplicates
        check_for_mac = self.tables_api.table_cam_read_entry(table_name=ARP_CACHE_TABLE_NAME, keys=ip) 
        entry_found = check_for_mac[0]
        entry_mac = check_for_mac[2]
        if entry_found and entry_mac == mac:
            return True
        return False
    
    def add_ARP_Cache_entry(self,ip,mac):
        self.tables_api.table_cam_add_entry(ARP_CACHE_TABLE_NAME, keys=ip, action_name="MyIngress.arp_match",action_data=mac)

    def handle_ARP_REPLY(self, pkt):
        check_ip_mac_found = self.check_ARP_Cache(pkt[ARP].prsc, pkt[ARP].hsrc)
        # if the ARP ip-mac source entry not in ARP CACHE - add it
        if check_ip_mac_found == False:
            self.add_ARP_Cache_entry(pkt[ARP].prsc, pkt[ARP].hsrc)
        self.sendp(pkt)

    def handle_ARP_REQUEST(self, pkt):
        # 1. send multiple arp requests per destination IP addr b4 sending
        # use initialized thread

        # check if the ARP packet hardware and IP source addresses are in the ARP Cache
        check_ip_mac_found = self.check_ARP_Cache(pkt[ARP].prsc, pkt[ARP].hsrc)
        # if the ARP ip-mac source entry not in ARP CACHE - add it
        if check_ip_mac_found == False:
            self.add_ARP_Cache_entry(pkt[ARP].prsc, pkt[ARP].hsrc)
            
        # check if IP exists -- check local ip table?
        if pkt[ARP].pdst in self.ifaces.ip:

            pkt[Ether].dst = pkt[Ether].src
            pkt[Ether].src = ifaces.mac # router mac address
            pkt[ARP].op = 2 # reply
            pkt[ARP].hwdst = pkt[ARP].hwsrc
            pkt[ARP].pdst = pkt[ARP].psrc
            pkt[ARP].hsrc = ifaces.mac
            pkt[ARP].psrc = pkt[ARP].pdst

        self.sendp(pkt)

    def handle_ICMPHostUnreachable(self, pkt):
        ICMP_pkt = icmp_pkt(self.rtable, self.ifaces, pkt, ICMP_UNREACH_TYPE, ICMP_HOST_UNREACH_CODE)
        self.sendp(ICMP_pkt)

