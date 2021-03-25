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

from control_plane.utils.addr_conversions import *

# TODO: update with the names you use for your routing table name and action
RTABLE_NAME = 'MyIngress.routing_table'
RTABLE_ACTION_NAME = 'MyIngress.ipv4_forward'
# TODO: update with the name you use for your arp cache table
ARP_CACHE_TABLE_NAME = 'MyIngress.arp_cache_table'

# TODO: update these with the names of all of your longest-prefix-match and
#       exact match hardware tables
LPM_TABLE_NAMES = [RTABLE_NAME]
EM_TABLE_NAMES = [ARP_CACHE_TABLE_NAME]


"""
The dictionaries KEYS_TO_NUMERIC, DATA_TO_NUMERIC, and NUMERIC_TO_DATA are keyed
by the table name and the value is a lambda function that converts period
delimited IP addresses and colon delimited MAC addresses to integers before
calling the p4_tables_api functions, and convert the return values back from
integers.

TODO: implement these dictionaries, or update the methods in Tables_api in
      tables.py if you wish to perform the conversions differently
"""

# A dictionary from table name -> lambda function that converts the keys for the
# table from their string form to their integer form
KEYS_TO_NUMERIC = {
    # E.g.
    # ARP_CACHE_TABLE_NAME:
    #    # arp_cache_table is keyed by an IP address
    #    lambda keys: [ip_to_int(keys[0])],
}

# A dictionary from table name -> lambda function that converts the action data
# for the table from string form to integer form
DATA_TO_NUMERIC = {
}

# A dictionary from table name -> lambda function that converts the action data
# for the table from integer form to string form
NUMERIC_TO_DATA = {
}

# Mac address for broadcast packets
ETH_BROADCAST = 'ff:ff:ff:ff:ff:ff'

# The value to use for the 'time to live' field when generating new packets
DEFAULT_TTL = 64

# A map from the string representation of an interface port to the binary
# representation. Port 1 is reserved for the CPU.
nf_port_map = {'nf0': 0b00000010, 'nf1': 0b00000011, 'nf2': 0b00000100, \
    'nf3': 0b00000101, 'dma0': 0b00000000}

# Digest codes that indicate why a packet was send to the control plane from the
# data plane
DIG_LOCAL_IP = 1
DIG_ARP_MISS = 2
DIG_ARP_REPLY = 3
DIG_TTL_EXCEEDED = 4
DIG_NO_ROUTE = 5

# ICMP types and codes
ICMP_ECHO_REPLY_TYPE = 0
ICMP_ECHO_REQUEST_TYPE = 8
ICMP_UNREACH_TYPE = 3
ICMP_TIME_EXCEEDED_TYPE = 11
ICMP_NET_UNREACH_CODE = 0
ICMP_HOST_UNREACH_CODE = 1
ICMP_PORT_UNREACH_CODE = 3

# The number of bytes of the original IP packet that generated an ICMP error to
# put into the ICMP payload
ICMP_DATA_SIZE = 28

# PWOSPF timer intervals
REQ_TIMEOUT = 1.0
CACHE_TIMEOUT = 15.0
LSUINT = 30.0
HELLOINT = 30.0
SLEEP_TIME = 1.0

# The area ID for routers in this PWOSPF network
ALLSPFRouters = '224.0.0.5'

# returns the iface corresponding to the port, if it exists
def port_to_iface(port, ifaces):
    match = list(filter(lambda i: i.port == port, ifaces))
    return match[0] if match else None

def icmp_pkt(routing_table, ifaces, pkt, icmp_type, icmp_code):
    if IP in pkt:
        match = routing_table.get(pkt[IP].src)
        if match: # don't send ICMP if not in routing table
            egress_port = match[1][0]
            iface = port_to_iface(egress_port, ifaces)
            ether = Ether(dst=ETH_BROADCAST, src=iface.mac)
            ip = IP(dst=pkt[IP].src, src=iface.ip)
            icmp = ICMP(type=icmp_type, code=icmp_code)
            data = str(pkt[IP])[:ICMP_DATA_SIZE] if \
                len(str(pkt[IP])) > ICMP_DATA_SIZE else str(pkt[IP])
            return ether / ip / icmp / data
    return None
