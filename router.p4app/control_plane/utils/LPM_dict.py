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

import socket, struct
from collections import namedtuple

from control_plane.utils.addr_conversions import int_to_ip

KEY_LEN = 32

"""
A structure that represents an entry in a longest prefix match dictionary
"""
LPM_entry = namedtuple('LPM_entry', ['key', 'prefix_len', 'val'])

"""
A dictionary that performs lookups using LPM instead of exact match
The keys must be string representations of an IP addresses
"""
class LPM_dict():
    """
    An error class that defines an exception that occurs when an entry is added
    to the LPM_dict that cannot be converted to an integer
    """
    class KeyError(TypeError):
        def __init__(self, key):
            self.message = 'Could not convert LPM key {} to int'.format(key)

    """
    Initializer

    @param entries a list of (key, prefix_len, val) to add to the dictionary
    """
    def __init__(self, *entries):
        self.entries = []
        for entry in entries:
            self.append(*entry)

    """
    Convert an IP address string to a long

    @param ip the address to convert
    @return a long that represents the same address as the ip parameter
    """
    def _ip2long(self, ip):
        packedIP = socket.inet_aton(ip)
        return struct.unpack("!L", packedIP)[0]

    """
    Adds an entry to the dictionary

    @param key a string representation of an IP address
    @param prefix_length the number of relevant bits in the key
    @param val the value to return when the table is matched on `key`.
               Will most likely be (action_name, [action_data])
    @raise KeyError if the key cannot be converted to a long
    """
    def append(self, key, prefix_len, val):
        try:
            key = self._ip2long(key)
        except:
            if type(key) != int: raise KeyError(key)
            pass
        self.entries.append(LPM_entry(key, prefix_len, val))
        # entries list is sorted by prefix length, longest to shortest
        self.entries = sorted(self.entries, key=lambda e: e.prefix_len,
            reverse=True)

    """
    Looks up an entry in the dictionary

    @param key a string representation of an IP address
    @return the value associated with the longest prefix match in the table for
            the key, or None if no match exacts
    @raise KeyError if the key cannot be converted to a long
    """
    def get(self, key):
        try:
            key = self._ip2long(key)
        except:
            if type(key) != int: raise KeyError(key)
            pass
        for e in self.entries:
            # values are sorted by key length, longest to shortest, so the
            # first match will be the longest
            if ((key >> (KEY_LEN - e.prefix_len)) == \
                (e.key >> (KEY_LEN - e.prefix_len))): return e.val
        return None

    """
    Removes all existing entries from the dictionary
    """
    def clear(self):
        self.entries = []

    """
    Creates a duplicate LPM_dict with the same entries as this one
    """
    def copy(self):
        new_dict = LPM_dict()
        new_dict.entries = list(self.entries)
        return new_dict

    """
    Converts the LPM_dict to a string representation where entries are separated
    by newlines and the ip address key is in string form
    """
    def __str__(self):
        e_strs = [str(e._replace(key=int_to_ip(e.key))) for e in self.entries]
        return '\n'.join(e_strs)

