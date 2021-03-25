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
# Based off of: https://github.com/secdev/scapy/blob/67a941b67bdeb571b64767f15a63f5235b1f38a6/scapy/contrib/ospf.py

from scapy.all import *

from control_plane.utils.consts import ALLSPFRouters, DEFAULT_TTL

PWOSPF_PROTO = 89

PWOSPF_HELLO_TYPE = 1
PWOSPF_LSU_TYPE = 4

PWOSPF_TYPES = {
    PWOSPF_HELLO_TYPE: 'HELLO',
    PWOSPF_LSU_TYPE: 'LSU'
}

def pwospf_chksum(pkt):
    p = bytes(pkt)
    return checksum(p[:16] + p[24:])

class PWOSPF(Packet):
    name = 'PWOSPF'
    fields_desc = [
        ByteField('version', 2),
        ByteEnumField('type', 1, PWOSPF_TYPES),
        ShortField('len', None),
        IPField('rid', '0.0.0.0'),
        IPField('aid', ALLSPFRouters),
        XShortField('chksum', None),
        # below unused in PWOSPF
        LEShortField('autype', 0),
        LELongField('auth1', 0),
        LELongField('auth2', 0)
    ]

    def post_build(self, p, pay):
        p += pay
        l = self.len
        if l is None:
            l = len(p)
            p = p[:2] + struct.pack("!H", l) + p[4:]
        # Checksum is calculated without authentication data
        # Algorithm is the same as in IP()
        if self.chksum is None:
            ck = pwospf_chksum(p)
            p = p[:12] + bytes([ck >> 8, ck & 0xff]) + p[14:]
        return p

class HELLO(Packet):
    name = 'HELLO'
    fields_desc = [
        IPField('mask', '0.0.0.0'),
        LEShortField('helloint', 0),
        LEShortField('padding', 0)
    ]

class Advertisement(Packet):
    name = 'Advertisement'
    fields_desc = [
        IPField('subnet', '0.0.0.0'),
        IPField('mask', '0.0.0.0'),
        IPField('rid', '0.0.0.0')
    ]

    # delineate between advertisements in the list
    def extract_padding(self, s):
        return '', s

class LSU(Packet):
    name = 'LSU'
    fields_desc = [
        LEShortField('seqno', 0),
        LEShortField('ttl', DEFAULT_TTL),
        FieldLenField('adcnt', None, count_of='ads'),
        PacketListField('ads', [], Advertisement,
            count_from=lambda pkt: pkt.adcnt,
            # length of an Advertisement packet
            length_from=lambda pkt: pkt.adcnt * 12)
    ]

bind_layers(IP, PWOSPF, proto=PWOSPF_PROTO)
bind_layers(PWOSPF, HELLO, type=PWOSPF_HELLO_TYPE)
bind_layers(PWOSPF, LSU, type=PWOSPF_LSU_TYPE)
