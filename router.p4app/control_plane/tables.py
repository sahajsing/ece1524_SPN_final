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
import os

from control_plane.utils.addr_conversions import *
from control_plane.utils.consts import *

"""
A structure that holds the information needed for a ternary match table entry
"""
TCAM_entry = namedtuple('TCAM_entry', ['addr', 'key', 'mask', 'action_name',
    'action_data'])

"""
Converts entries for a longest prefix match table into those for a ternary match
table

@param lpm_dict an LPM_dict instance that should be converted to a list of tcam
                entries
@return a list of TCAM_entry
"""
def lpm_to_tcam(lpm_dict):
    lpm_entries = lpm_dict.entries
    tcam_entries = []

    addr = 0
    for e in lpm_entries:
        mask = 0
        for i in range(e.prefix_len):
            mask += 1 << (31 - i)
        try:
            # val should be (action_name, action_data)
            action_name, action_data = e.val
            tcam_entries.append(TCAM_entry(addr, e.key, mask, action_name,
                action_data))
            addr += 1
        except:
            pass

    return tcam_entries

"""
This class implements wrapper functions for p4_tables_api (or an equivalent
hardware tables API) that convert period delimited IP addresses and colon
delimited MAC addresses to integers before calling the p4_tables_api functions,
and convert the return values back from integers
"""
class Tables_api():
    """
    Initializer

    @param hw_api the module on which to call methods to actually populate the
                  tables
    """
    def __init__(self, hw_api):
        self.hw_api = hw_api

    """
    Looks up an entry in an exact match table

    @param table_name the table in which to look up
    @param keys the input to the table to look up
    @return a tuple (found, action_name, action_data) where found is a boolean
    """
    def table_cam_read_entry(self, table_name, keys):
        keys = KEYS_TO_NUMERIC[table_name](keys)

        found, action_name, action_data = \
            self.hw_api.table_cam_read_entry(table_name, keys)

        action_data = NUMERIC_TO_DATA[table_name](action_data)

        return (found, action_name, action_data)

    """
    Adds an entries to an exact match table

    @param table_name the table to which to add the entry
    @param keys the data on which to match
    @param action_name the name of the action that should get executed when
                       there is a match in the table
    @param action_data the parameters that should be passed to action_name when
                       these keys are matched in the table
    """
    def table_cam_add_entry(self, table_name, keys, action_name, action_data):
        keys = KEYS_TO_NUMERIC[table_name](keys)
        action_data = DATA_TO_NUMERIC[table_name](action_data)

        self.hw_api.table_cam_add_entry(table_name, keys, action_name,
            action_data)

    def table_cam_delete_entry(self, table_name, keys):
        keys = KEYS_TO_NUMERIC[table_name](keys)

        self.hw_api.table_cam_delete_entry(table_name, keys)

    """
    Populates a ternary match table as though it is a longest prefix match table.
    Cleares the table before adding entries so that when the method returns the
    table only contains those entries from the lpm_dict parameter.

    @param table_name the name of the table into which entries should be loaded
    @param lpm_dict an LPM_dict containing entries to load into the table
    """
    def table_lpm_load_dataset(self, table_name, lpm_dict):
        self.hw_api.table_tcam_clean(table_name)
        map(lambda e: self.hw_api.table_tcam_write_entry(table_name, \
                e.addr, [e.key], [e.mask], e.action_name, \
                DATA_TO_NUMERIC[table_name](e.action_data)),
                lpm_to_tcam(lpm_dict))
"""
This class is the hardware table api that should be used as the initialization
argument to Tables_api when running the router in bmv2.
"""
class Bmv2_grpc_tables_api():
    """
    Initializer

    @param switch the Mininet/p4app switch object
    """
    def __init__(self, switch):
        self.sw = switch
        self.table_cache = {}

    def _add_entry(self, entry):
        table_name = entry['table_name']
        if table_name not in self.table_cache: self.table_cache[table_name] = []
        self.table_cache[table_name].append(entry)
        self.sw.insertTableEntry(entry=entry)

    def _clear_table(self, table_name):
        if table_name not in self.table_cache: return
        for entry in self.table_cache[table_name]:
            self.sw.removeTableEntry(entry)
        self.table_cache[table_name] = []

    """
    TODO(Steve): implement ...
    """
    def table_cam_read_entry(self, table_name, keys):
        return (True, '', [])

    """
    Adds an entries to an exact match table

    @param table_name the table to which to add the entry
    @param keys the data on which to match
    @param action_name the name of the action that should get executed when
                       there is a match in the table
    @param action_data the parameters that should be passed to action_name when
                       these keys are matched in the table
    """
    def table_cam_add_entry(self, table_name=None, match_fields=None, action_name=None, action_params=None):
        entry = dict(table_name=table_name, match_fields=match_fields,
                action_name=action_name, action_params=action_params)
        self._add_entry(entry)

    """
    TODO(Steve): implement ...
    """
    def table_cam_delete_entry(self, table_name, keys):
        pass

    """
    Populates a ternary match table as though it is a longest prefix match table.
    Cleares the table before adding entries so that when the method returns the
    table only contains those entries from the lpm_dict parameter.

    @param table_name the name of the table into which entries should be loaded
    @param lpm_dict an LPM_dict containing entries to load into the table
    """
    def table_lpm_load_dataset(self, table_name, lpm_dict):
        assert table_name == RTABLE_NAME
        self._clear_table(table_name)
        priority = len(lpm_dict.entries)
        for e in lpm_to_tcam(lpm_dict):
            assert e.action_name == RTABLE_ACTION_NAME
            port, next_addr = e.action_data
            entry = dict(table_name=RTABLE_NAME,
                        match_fields={'p.ip.dstAddr': [e.key, e.mask]},
                        priority=priority,
                        action_name='MyIngress.ipv4_forward',
                        action_params={'port': port, 'next': next_addr})
            priority -= 1
            if e.key == 0 and e.mask == 0:
                del entry['match_fields']
            self._add_entry(entry)


"""
This class populates p4 tables given an API
TODO: Implement this class so that it populates your P4 tables
"""
class Tables_populator():
    """
    Initializer

    @param api a Tables_api instance (or module with equivalent methods) whose
               methods should be called in order to populate the tables
    """
    def __init__(self, api):
        self.api = api


    """
    Populates relevant p4 tables given a list of interfaces

    @param ifaces a list of Iface objects representing the interfaces (of this
                  router) for which to add table entries
    """
    def load_ifaces(self, ifaces):
        """
        TODO
        E.g., self.api.table_cam_add_entry(TABLE_NAME, match_fields={...}, action_name='...', action_params={...})
        """
        for iface in ifaces:
            self.api.table_cam_add_entry(table_name='MyIngress.local_ip_table',keys={'p.ip.dstAddr':iface.ip}, action_name='MyIngress.send_to_cpu',action_data={'DIG_CODE':DIG_LOCAL_IP})
        pass


    """
    Populates relevant p4 tables given a routing table

    @param rtable an LPM_dict instance containing the forwarding table for which
                  to add table entries
    """
    def load_rtable(self, rtable):
        """
        TODO
        E.g., self.api.table_lpm_load_dataset(RTABLE_NAME, rtable)
        """
        self.api.table_lpm_load_dataset(RTABLE_NAME, rtable)
        pass

    """
    Populates relevant p4 tables given a list of arp cache entries

    @param arp_cache a list of (ip, mac) tuples that represent entries in the
                     arp cache
    """
    def load_arp_cache(self, arp_cache):
        """
        TODO
        E.g., self.api.table_cam_add_entry(TABLE_NAME, match_fields={...}, action_name='...', action_params={...})
        """
        for arp in arp_cache:
            self.api.table_cam_add_entry(ARP_CACHE_TABLE_NAME, keys={'p.arp.dstIP':arp[0]},action_name='MyIngress.arp_match',action_data={'dstAddr':arp[1]})
