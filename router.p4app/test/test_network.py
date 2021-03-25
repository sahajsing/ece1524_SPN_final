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

from collections import defaultdict, namedtuple

from control_plane.config import Iface, RTABLE_ACTION_NAME
from control_plane.utils.addr_conversions import ip_to_int, int_to_ip, mask_to_prefix_len
from control_plane.utils.consts import nf_port_map
from control_plane.utils.LPM_dict import LPM_dict

# NOTE: We assume that your data-plane routing table input parameters are
#       [dst_port, next_hop_ip]. If you're routing table is of a different
#       format in your P4 program, you will need to update below

NEIGHBOR_MASK = '255.255.255.254'

Neighbor = namedtuple('Neighbor', ['iface', 'router'])

class Router():
    def __init__(self):
        self.ifaces = []
        self.rid = None
        self.neighbors = defaultdict(lambda: [])

    def add_iface(self, iface):
        self.ifaces.append(iface)
        if self.rid is None: self.rid = iface.ip

    def add_neighbor(self, iface_ip, neighbor):
        self.neighbors[iface_ip].append(neighbor)

    # returns the interface of a neighbor
    def niface(self, ip):
        if len(self.neighbors[ip]) > 0:
            return self.neighbors[ip][0].iface

        return None

class Test_network():
    def __init__(self):
        self.rself = Router()
        self.r0 = Router()
        self.r1 = Router()
        self.r2 = Router()
        self.r3 = Router()
        self.r4 = Router()

        # links from self to neighbors
        self._add_link(self.rself, self.r0, nf_port_map['nf0'], '10.6.0.3',
            NEIGHBOR_MASK)
        self._add_link(self.rself, self.r1, nf_port_map['nf1'], '10.6.1.3',
            NEIGHBOR_MASK)
        self._add_link(self.rself, self.r2, nf_port_map['nf2'], '10.6.2.3',
            NEIGHBOR_MASK)
        # end host
        self._add_link(self.rself, None, nf_port_map['nf3'], '10.6.3.3',
            NEIGHBOR_MASK)

        # links between other routers
        self._add_link(self.r0, self.r2, None, '10.2.0.2', NEIGHBOR_MASK)
        self._add_link(self.r0, self.r3, None, '10.0.0.3', NEIGHBOR_MASK)
        self._add_link(self.r1, self.r3, None, '10.1.0.3', NEIGHBOR_MASK)
        self._add_link(self.r3, self.r4, None, '10.3.0.3', NEIGHBOR_MASK)
        self._add_link(self.r3, None, None, '10.3.1.3', '0.0.0.0')
        self._add_link(self.r4, None, None, '10.4.0.3', '255.255.0.0')

        self.rtable = LPM_dict()
        self._populate_rtable()

    def _add_link(self, r1, r2, port, ip, mask):
        iface1 = Iface(port, ip, mask, self._ip_to_mac(ip))
        other_ip = None
        if mask == NEIGHBOR_MASK:
            int_ip = ip_to_int(ip)
            other_ip = int_ip + 1 if int_ip % 2 == 0 else int_ip - 1
            other_ip = int_to_ip(other_ip)
        iface2 = Iface(port, other_ip, mask, self._ip_to_mac(other_ip))

        r1.add_iface(iface1)
        r1.add_neighbor(iface1.ip, Neighbor(iface2, r2))

        if r2 is not None: # if not endhost, firewall, etc.
            r2.add_iface(iface2)
            r2.add_neighbor(iface2.ip, Neighbor(iface1, r1))

    def _populate_rtable(self):
        candidates = [] # routers to go through to add to routing table
        seen_subs = [] # subnets that have already been added
        seen_routers = [] # routers whose interfaces have already been added

        def _add_to_rtable(ip, mask, port, gw):
            key = int_to_ip(ip_to_int(ip) & ip_to_int(mask))
            length = mask_to_prefix_len(mask)

            if (key, length) in seen_subs: return
            seen_subs.append((key, length))

            # TODO: update if your data-plane routing table input parameters
            #       are not [dst_port, next_hop_ip]
            self.rtable.append(key, length, (RTABLE_ACTION_NAME, [port, gw]))

        # create routing table breadth-first through neighbors
        for i in self.rself.ifaces:
            _add_to_rtable(i.ip, i.mask, i.port, '0.0.0.0')

            ns = self.rself.neighbors[i.ip]
            candidates.extend((i.port, n.router, n.iface.ip) for n in ns)

        while candidates:
            (port, router, gw) = candidates[0]
            del candidates[0]
            if not router or router in seen_routers: continue
            seen_routers.append(router)

            for iface in router.ifaces:
                _add_to_rtable(iface.ip, iface.mask, port, gw)
                candidates.extend([(port, n.router, gw) for n in
                    router.neighbors[iface.ip]])

    # converts an IP address to a mac address
    # ex: 10.6.0.3 => 08:88:10:06:00:03
    def _ip_to_mac(self, ip):
        if not ip: return None
        mac = '08:88'
        components = ip.split('.')
        for c in components:
            if len(c) > 2: c = c[:2]
            if len(c) == 1: c = '0' + c
            mac = mac + ':' + c
        return mac

    def __str__():
        return """## Network Topology - 10.0.0.0/8 network ##
               ##################
               eh0 - ip: 10.6.3.2
               ##################
                       |
                       |
                iface3:10.6.3.3   iface2:
             #################### 10.6.2.3        ##################
             self - rid: 10.6.0.3 --------------- r2 - rid: 10.6.2.2
             ####################        10.6.2.2 ##################
     iface1:10.6.1.3     iface0:10.6.0.3      10.2.0.3
            /                     \\               /
           /                       \\             /
     10.6.1.2                    10.6.0.2    10.2.0.2
##################                ##################
r1 - rid: 10.6.1.2                r0 - rid: 10.6.0.2
##################                ##################
       10.1.0.3                  10.0.0.3
           \\                       /
            \\                     /
           10.1.0.2          10.0.0.2
               ################## 10.3.1.3      #########################
               r3 - rid: 10.3.0.3 ------------- default route to internet
               ##################     0.0.0.0/0 #########################
                    10.3.0.3
                       |
                       |
                    10.3.0.2
              ################## 10.4.0.3        ########
              r4 - rid: 10.4.0.3 --------------- firewall
              ##################     10.4.0.0/16 ########
"""
