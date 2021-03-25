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
import json

import sys, os
from control_plane.tables import Tables_populator
from control_plane.utils.addr_conversions import ip_to_int, int_to_ip, mask_to_prefix_len
from control_plane.utils.consts import *
from control_plane.utils.LPM_dict import LPM_dict

"""
Contains fields relevant to a router's interface
"""
class Iface():
    """
    Initializes the interface

    @param port the binary representation of the port of the router
                corresponding to this interface
    @param ip the IP address of this interface (most likely in string format)
    @param mask the network mask that determines the subnet that the IP address
                of this interface corresponds to. For example, a mask of
                '255.255.0.0' corresponds to a /16 subnet (most likely in string
                format)
    @param mac the ethernet address of this interface
    """
    def __init__(self, port, ip, mask, mac):
        self.port = port
        self.ip = ip
        self.mask = mask
        self.mac = mac

    """
    Determines whether or not an IP address is within the subnet of the link
    from this interface

    @param ip the IP address to check
    @return True if ip is within the subnet of this interface, False otherwise
    """
    def in_subnet(self, ip):
        mask = ip_to_int(self.mask)
        return ip_to_int(ip) & mask == ip_to_int(self.ip) & mask

    """
    Generates a string representation of the subnet that this interface is a
    part of. For example, if the interface had IP address 127.9.12.123 and mask
    255.255.0.0, the subnet string would be '127.9.0.0'

    @return a string representation of the interface's subnet
    """
    def subnet_str(self):
        return int_to_ip(ip_to_int(self.mask) & ip_to_int(self.ip))

"""
Stores configuration information for the control plane
"""
class Config():
    """
    Initializes the configuration object

    @param tables_api the api to use to populate p4 tables. This must have the
                      same properties as Tables_api in tables.py, including
                      table_cam_add_entry and table_lpm_load_dataset.
    @param pwospf_enabled True if the routing table should be generated using
                          the PWOSPF protocol, false if we should use a static
                          routing table
    @param dma_iface the interface over which the control plane and the data
                     plane exchange packets (most likely in string format)
    @param sendp the function to use to send packets to the data plane. Must
                 take a single parameter that is the packet to send.
    @param ifaces a list of Iface objects that correspond to the router's
                  interfaces
    @param rtable an LPM_dict that contains routing table entries
    """
    def __init__(self, tables_api, pwospf_enabled=False, dma_iface=None,
        sendp=None, ifaces=None, rtable=None, req_timeout=REQ_TIMEOUT,
        cache_timeout=CACHE_TIMEOUT, helloint=HELLOINT, lsuint=LSUINT,
        sleep_time=SLEEP_TIME):

        self.tables_api = tables_api
        self.pwospf_enabled = pwospf_enabled
        self.dma_iface = dma_iface
        self.sendp = sendp if sendp is not None else self.send_to_dp
        self.ifaces = [] if ifaces is None else ifaces
        self.rtable = LPM_dict() if rtable is None else rtable
        self.req_timeout = req_timeout
        self.cache_timeout = cache_timeout
        self.helloint = int(helloint)
        self.lsuint = int(lsuint)
        self.sleep_time = sleep_time

    """
    Forwards a packet to the dataplane over the dma interface

    @param pkt the packet to forward
    """
    def send_to_dp(self, pkt):
        print_send = 0
        if print_send:
            print("Sending packet over DMA: -----------")
            pkt.show()
            print("-------------- END PKT -------------")
        sendp(pkt, iface=self.dma_iface, verbose=False)

    """
    Retrieves information about the router's interfaces and routing table from
    a file, populating the `ifaces` and `rtable` fields of the object.
    The file should be formatted as follows:
    "interfaces": { [port] :  {"ip" : [ip], "mac": [mac]} },
    "routing_table": [ {"subnet": [subnet], "netmask": [mask],
      "gw": [next hop ip], "dev": [egress port] } ]
    A malformed configuration file is a fatal error and will cause the program
    to exit.

    @param filename the path to the configuration file
    """
    def parse_config_file(self, filename):
        with open(filename, 'r') as f:
            try:
                config = json.load(f)
                self.parse_config(config)
            except Exception as e:
                print('Configuration file invalid: ')
                print(e)
                raise e
                exit(1)

    def parse_config(self, config):
        for nf, val in config['interfaces'].items():
            ip = val['ip']
            mask = val['netmask']
            mac = val['mac']
            self.ifaces.append(Iface(nf_port_map[nf], ip, mask, mac))
        for entry in config['routing_table']:
            subnet = entry['subnet']
            mask = entry['netmask']
            gw = entry['gw']
            port = entry['dev']
            # TODO: if your action data is not (egress port,
            #       next hop), update this
            self.rtable.append(subnet, mask_to_prefix_len(mask),
                (RTABLE_ACTION_NAME, [nf_port_map[port], gw]))

    """
    Fills the p4 tables with information about the router's interfaces and, if
    PWOSPF is disabled, the routing table
    """
    def populate_tables(self):
        print('Initializing table entries...')
        tables_populator = Tables_populator(self.tables_api)
        tables_populator.load_ifaces(self.ifaces)
        # if PWOSPF is enabled, it is the job of the PWOSPF handler to populate
        # the routing table
        if not self.pwospf_enabled: tables_populator.load_rtable(self.rtable)
