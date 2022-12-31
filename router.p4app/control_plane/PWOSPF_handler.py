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

from collections import defaultdict,namedtuple

STARTING_SEQNO = 1

Neighbor = namedtuple('Neighbor',['iface','routerID','last_hello_time'])

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
        self.neighbors = {}
        self.lsu_last_pkts = {} # dict of {routerID: last_lsu_pkt}
        self.lsu_adj_list = {}


        # TODO: may want to create threads for sending HELLO and LSU updates as
        # well as for timing out stale topology entries
    def addNeighbor(self, ingress_iface, ifaceIP, rid):
        time_received = 0
        if (ingress_iface not in self.neighbors):
            self.neighbors[ingress_iface] = [[(ifaceIP, rid), time_received]]
        else:
            self.neighbors[ingress_iface].append([(ifaceIP,rid),time_received])

    def removeNeighbor(self,ingress_iface, ifaceIP, rid):
        if (ingress_iface in self.neighbors):
            for neighbor in self.neighbors[ingress_iface]:
                if (ifaceIP, rid) == neighbor[0]: # found neighbor in interface
                    self.neighbors[ingress_iface].remove(neighbor)

    
    def hasNeighbor(self,ingress_iface, ifaceIP, rid):
        if (ingress_iface in self.neighbors):
            for neighbor in self.neighbors[ingress_iface]:
                if (ifaceIP, rid) == neighbor[0]: # found neighbor in interface
                    return True
        return False
    
    # def getNeighborUpdateTime(self, rid, ifaceIP):

    def setNeighborTimeReceived(self,ingress_iface, ifaceIP, rid, updated_Time):
        for neighbor in self.neighbors[ingress_iface]:
            ip_rid = neighbor[0]
            if ip_rid == (ifaceIP,rid):
                neighbor[1] = updated_Time





    def handle_hello(self,pkt,ingress_iface):
        # verify mask and helloint of HELLO pkt match receiving iface
        if pkt[HELLO].mask != ingress_iface.mask: return
        # if pkt[HELLO].helloint != ingress_iface.helloint: return

        # match source IP of HELLO pkt to receiving iface neighbor's
        ifaceIP = pkt[IP].src

        # if no neighbor --> create one 
        # if interface has neighbors but not src IP --> add one 
        # if matched neighbor --> update neighbor's "last HELLO pkt received" timer
        if self.hasNeighbor(ingress_iface,ifaceIP, self.rid):
            # update timer
            self.setNeighborTimeReceived(ingress_iface, ifaceIP, self.rid, time.time())
        else:
            self.addNeighbor(ingress_iface, ifaceIP,self.rid)
            # add neighbor


    def handle_lsu(self, pkt, infress_iface):
        # drop packet generaed from this router 
        pkt_rid = pkt[PWOSPF].rid
        if pkt_rid == self.rid: return

        if pkt_rid in self.lsu_last_pkts:
            last_pkt = self.lsu_last_pkts[pkt_rid]
            if pkt[LSU].seqno == last_pkt[LSU].seqno: return



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
            # timed out. 
            # If the neighbor is not known, add it to the database,
            # rebuild the database, and send link state updates to the router's
            # neighbors to notify them of the change
            pass
        elif LSU in pkt:
            self.handle_lsu(pkt, ingress_iface)
            # TODO: when an LSU packet is received: 
            # 1. drop packets generated from this router. 
            # 2. If the neighbor is known, drop packet if it has
            # the same seqno as the most recently received packet from that
            # neighbor. 
            # 3. If it is a new packet, update the timestamp and seqno
            # of the router. 
            # 4. If the router has new advertisements, save them.
            # 5. If the router was not knon, add it to the topology. 
            # 6. If a router had new advertisements or it was a new router, 
            #       rebuild the routing table. Forward all packets with
            #       new sequence numbers to all neighbors.
            pass

# verifications
#   1. version number = 2
#   2. 16 bit checksum verified
#   3. area ID in PWOSPF header must match Area ID of receiving router 
#   4. Auth type must be same for receiving router
'''
HELLO validity   
    1. check validity of IP header and PWOSPF packet header 
    2. Network Mask and Helloint fields on recived HELLO pkt
       checked agianst valued for receiving interface = drop if not
    3. match source of Hello pkt to one of receiving iface's neighbors
        - source = IP src addr in HELLO IP header
        -  current neighbor = in iface data structure
        - if no neighbor = create one
        - if iface has neihbor(s) but none match ip incoming pkt - 
            new neighor added
        - if neighbor matched  neighbors "last hello pkt received" timer
            updated
HELLO pkts
    - sent to dest IP address ALLSPFRouters = '224.0.0.5
'''
'''
LSU validity pkts
    1. if LSU gen by receiving router = dropped
    2. if seq # matches last pkt received from sending host = dropped
    3. if pkt contents = pkt contents of last received from sending host
        = host db not updated, pkt ignored
    4. if LSU from host not in db = pkt contents used to update db
        & Djikstra's algo used to recompute fwding table
    5. if LSU data for host in db but info changed = LSU used to update
        db & Djikstra's to recompute fwding table 
    6. all received pkts w/ new seq #'s = flooded to all neigbors except 
        incoming neighbor of pkt
    7. ttl header checked in fwding stage - not when local handle
    8. ttl field of all flooded pkts dec before exiting router
        - if 0 before exit, pkt must not be flooded
LSU Pkts
    - sent point to point using IP addr of neighboring iface as dest
'''