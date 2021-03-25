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

import re
from ipaddress import IPv4Address

"""
Converts a string IP address to its integer form

@param key the string IP address (e.g. '127.0.0.1')
@return the IP address as a 32-bit integer
"""
def ip_to_int(key):
    if isinstance(key, int): return key
    return int(IPv4Address(str(key)))

"""
Converts an integer IP address to its string representation

@param key a 32-bit integer representing an IP address
@return the string representation of the IP address
"""
def int_to_ip(key):
    if isinstance(key, str): return key
    return str(IPv4Address(key))

# a regex that matches the string representation of a mac address
# e.g. 08:88:88:88:88:88
MAC_STR_REGEX = r'([\dA-Fa-f]{2}:){5}[\dA-Fa-f]{2}'

"""
Converts a string mac address to its integer form

@param key a string mac address (e.g. '08:88:88:88:88:88')
@return a 48-bit integer of the mac address
@raise ValueError if `key` is not a properly formatted string mac address
"""
def mac_to_int(key):
    if isinstance(key, basestring): key = str(key)
    if str != type(key) or 17 != len(key) or not re.match(MAC_STR_REGEX, key):
        raise ValueError

    return int(key.translate(None, ":.- "), 16)

"""
Converts an integer mac address to its string representation

@param key the mac address in integer form
@return a string representation of a mac address
@raise ValueError if the key param is not an int
"""
def int_to_mac(key):
    if int != type(key): raise ValueError

    mac_hex = "{:012x}".format(key)
    mac_str = ":".join(mac_hex[i:i+2] for i in range(0, len(mac_hex), 2))

    return mac_str

"""
Creates an IP address mask given the relevant prefix length
Example: 16 => '255.255.0.0'

@param prefix_len an integer with the relevant prefix length
@return a string IP address that is the mask
@raise ValueError if the prefix_len param is not an int
"""
def prefix_len_to_mask(prefix_len):
    if int != type(prefix_len): raise ValueError

    mask = 0
    for i in range(prefix_len):
        mask |= 1 << (31 - i)
    return int_to_ip(mask)

"""
Determines the length of an IP address mask
Example: '255.255.0.0' => 16

@param mask an IP address mask (likely in string form)
@return an integer that is the length of the prefix
"""
def mask_to_prefix_len(mask):
    mask = ip_to_int(mask)
    if 0 == mask: return 0

    num_zeros = 0
    while mask % 2 == 0:
        num_zeros += 1
        mask = mask >> 1
    prefix_len = 32 - num_zeros

    return prefix_len

