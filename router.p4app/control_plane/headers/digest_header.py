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


from scapy.all import bind_layers, ByteField, Packet, Ether

class Digest_data(Packet):
    name = 'Digest_data'
    fields_desc = [
        ByteField("src_port", 0),
        ByteField("digest_code", 0)
    ]
    def mysummary(self):
        return self.sprintf("src_port=%src_port% digest_code=%digest_code%")

bind_layers(Digest_data, Ether)

