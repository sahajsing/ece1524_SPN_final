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

from datetime import datetime, timedelta
from threading import Thread, Lock

from control_plane.headers.PWOSPF_headers import *
from control_plane.utils.consts import ETH_BROADCAST, nf_port_map

STARTING_SEQNO = 1

"""
The PWOSPF_handler handles incoming PWOSPF packets and generates outgoing PWOSPF
packets. It should maintain a database of the topology and update the p4 routing
table whenever the topology changes.
"""
class PWOSPF_handler():
    """
    Initializes the handler

    @param config a Config
    @param aid the PWOSPF area id that this router belongs in
    """
    def __init__(self, config, aid=ALLSPFRouters):
        self.sendp = config.sendp
        self.aid = aid
        self.ifaces = config.ifaces
        # the router id for PWOSPF should be the IP address of the 0th interface
        self.rid = list(filter(lambda i: i.port == nf_port_map['nf0'],
            self.ifaces))[0].ip

        # TODO: may want to create threads for sending HELLO and LSU updates as
        # well as for timing out stale topology entries


    """
    Processes received PWOSPF packets

    @param pkt the packet to process
    @param src_port the port on which this packet was received
    """
    def handle_pkt(self, pkt, src_port):
        ingress_iface = list(filter(lambda iface: iface.port == src_port,
            self.ifaces))[0]
        if HELLO in pkt:
            self.handle_hello(pkt, ingress_iface)
            # TODO: when a HELLO packet is received: if the neighbor is known,
            # update the time received field so that the neighbor does not get
            # timed out. If the neighbor is not known, add it to the database,
            # rebuild the database, and send link state updates to the router's
            # neighbors to notify them of the change
            pass
        elif LSU in pkt:
            self.handle_lsu(pkt, ingress_iface)
            # TODO: when an LSU packet is received: drop packets generated from
            # this router. If the neighbor is known, drop packet if it has
            # the same seqno as the most recently received packet from that
            # neighbor. If it is a new packet, update the timestamp and seqno
            # of the router. If the router has new advertisements, save them.
            # If the router was not know, add it to the topology. If a router
            # had new advertisements or it was a new router, rebuild the routing
            # table. Forward all packets with new sequence numbers to all
            # neighbors.
            pass
