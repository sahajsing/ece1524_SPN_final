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
        self.tables_api = config.tables_api
        self.ifaces = config.ifaces
        self.sendp = config.sendp
        self.rtable = config.rtable

        # TODO: initialize ARP handling thread(s)?
        # TODO: define additional helper methods
        # One possible approach for handling the ARP cache is to define two
        # additional threads:
        # 1. To send multiple arp requests per destination ip address before
        #    sending and ICMP host unreachable if none of the requests receive
        #    a response
        # 2. To remove stale cache entries

