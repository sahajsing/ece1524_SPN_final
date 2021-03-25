#!/usr/bin/env python

#
# Copyright (c) 2017 Stephen Ibanez, 2021 Theo Jepsen
# All rights reserved.
#
# This software was developed by Stanford University and the University of Cambridge Computer Laboratory
# under National Science Foundation under Grant No. CNS-0855268,
# the University of Cambridge Computer Laboratory under EPSRC INTERNET Project EP/H040536/1 and
# by the University of Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249 ("MRC2"),
# as part of the DARPA MRC research programme.
#

from control_plane.utils.consts import EM_TABLE_NAMES, LPM_TABLE_NAMES
from control_plane.utils.LPM_dict import LPM_dict

class Table_not_found_exception(Exception):
    def __init__(self, table_name):
        Exception.__init__(self, '{} is not a valid table name'.format(table_name))

class Sim_tables_api():
    """
    A python implementation of the p4_tables_api
    For use testing the control plane independently of the hardware
    """
    def __init__(self):
        self.lpm_tables = {
            table_name : LPM_table() for table_name in LPM_TABLE_NAMES
        }
        self.em_tables = {
            table_name : EM_table() for table_name in EM_TABLE_NAMES
        }

    def table_cam_read_entry(self, table_name, keys):
        table = self.em_tables.get(table_name)
        if not table:
            raise Table_not_found_exception(table_name)

        return table.read_entry(keys)

    #def table_cam_add_entry(self, table_name, keys, action_cb, action_params):
    def table_cam_add_entry(self, table_name=None, match_fields=None, action_name=None, action_params=None):
        action_cb = action_name
        action_params = list(action_params.values())
        keys = list(match_fields.values())
        table = self.em_tables.get(table_name)
        if not table:
            raise Table_not_found_exception(table_name)

        table.add_entry(keys, action_cb, action_params)

    def table_cam_delete_entry(self, table_name, keys):
        table = self.em_tables.get(table_name)
        if not table:
            raise Table_not_found_exception(table_name)

        table.delete_entry(keys)

    def table_lpm_load_dataset(self, table_name, lpm_dict):
        table = self.lpm_tables.get(table_name)
        if not table:
            raise Table_not_found_exception(table_name)

        table.load_dataset(lpm_dict)


class Match_table(object):
    def __init__(self):
        self.entries = []
        self.default_action = None
        self.default_action_params = None

    def set_default(self, action_cb, action_params):
        self.default_action = action_cb
        self.default_action_params = action_params


class EM_table(Match_table):
    def __init__(self):
        Match_table.__init__(self)

    def add_entry(self, keys, action_cb, action_params):
        self.entries.append((keys, action_cb, action_params))

    def read_entry(self, match_vals):
        for (keys, action_cb, action_params) in self.entries:
            if match_vals == keys:
                return ('True', action_cb, action_params)

        return ('False', None, None)

    def delete_entry(self, match_vals):
        entry = None
        for (keys, action_cb, action_params) in self.entries:
            if match_vals == keys:
                entry = (keys, action_cb, action_params)
                break

        if entry:
            self.entries.remove(entry)

    def apply(self, match_vals, pkt_and_meta):
        for (keys, action_cb, action_params) in self.entries:
            if match_vals == keys:
                action_cb(pkt_and_meta, *action_params)
                return (True, action_cb)
        if (self.default_action is not None):
            self.default_action(pkt_and_meta, *self.default_action_params)
        return (False, self.default_action)

class LPM_table(Match_table):
    def __init__(self):
        Match_table.__init__(self)
        self.entries = LPM_dict()

    def load_dataset(self, lpm_dict):
        self.entries = lpm_dict

    def add_entry(self, key, key_len, prefix_len, action_cb, action_params):
        self.entries.append(key, key_len, prefix_len, (action_cb, action_params))

    def apply(self, match_val, pkt_and_meta):
        match = self.entries.get(match_val)
        if match:
            action_cb, action_params = match
            action_cb(pkt_and_meta, *action_params)
            return (True, action_cb)

        if (self.default_action is not None):
            self.default_action(pkt_and_meta, *self.default_action_params)
        return (False, self.default_action)

