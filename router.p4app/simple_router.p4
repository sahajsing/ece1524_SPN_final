//
// Copyright (c) 2017 Stephen Ibanez, 2021 Theo Jepsen
// All rights reserved.
//
// This software was developed by Stanford University and the University of Cambridge Computer Laboratory
// under National Science Foundation under Grant No. CNS-0855268,
// the University of Cambridge Computer Laboratory under EPSRC INTERNET Project EP/H040536/1 and
// by the University of Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249 ("MRC2"),
// as part of the DARPA MRC research programme.
//


#include <core.p4>
#include <v1model.p4>


typedef bit<9>  port_t;
typedef bit<48> EthAddr_t;
typedef bit<32> IPv4Addr_t;

const bit<16> IP_TYPE = 16w0x0800;
const bit<16> ARP_TYPE = 16w0x0806;

const bit<4> IPv4 = 4w0x4;

const port_t CPU_PORT = 1;

typedef bit<8> digCode_t;
const digCode_t DIG_LOCAL_IP = 1;
const digCode_t DIG_ARP_MISS = 2;
const digCode_t DIG_ARP_REPLY = 3;
const digCode_t DIG_TTL_EXCEEDED = 4;
const digCode_t DIG_NO_ROUTE = 5;

// standard Ethernet header
header Ethernet_h {
    EthAddr_t dstAddr;
    EthAddr_t srcAddr;
    bit<16> etherType;
}

// TODO: What other headers do you need to add support for?

/* Here we define a digest_header type. This header contains information
 * that we want to send to the control-plane. This header should be
 * prepended to all packets sent to the control-plane.
 */
// Digest header
header digest_header_h {
    bit<8>   src_port;
    bit<8>   digest_code;
}

// List of all recognized headers
struct Parsed_packet {
    Ethernet_h ethernet;
    digest_header_h digest;
}

// user defined metadata: can be used to shared information between
// MyParser, MyIngress, and MyDeparser
struct user_metadata_t {
}

// Parser Implementation
parser MyParser(packet_in b,
                 out Parsed_packet p,
                 inout user_metadata_t user_metadata,
                 inout standard_metadata_t standard_metadata) {
    // TODO: Parse any additional headers that you add
    state start {
        b.extract(p.ethernet);
        transition accept;
    }
}

control MyVerifyChecksum(inout Parsed_packet p, inout user_metadata_t meta) {
    apply {
        // TODO: Verify the IPv4 checksum
    }
}

// match-action pipeline
control MyIngress(inout Parsed_packet p,
                inout user_metadata_t user_metadata,
                  inout standard_metadata_t standard_metadata) {

    // TODO: Declare your actions and tables

    action set_output_port(port_t port) {
        standard_metadata.egress_spec = port;
    }

    // TODO: Is this what the routing table is supposed to look like?
    table routing_table {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            set_output_port;
            NoAction;
        }
        size = 63;
        default_action = NoAction;
    }


    apply {
        // TODO: Define your control flow
        routing_table.apply();
    }
}

// Deparser Implementation
control MyDeparser(packet_out b,
                    in Parsed_packet p) {
    apply {
        // TODO: Emit other headers you've defined
        b.emit(p.digest);
        b.emit(p.ethernet);
    }
}

control MyEgress(inout Parsed_packet hdr,
                 inout user_metadata_t meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout Parsed_packet hdr, inout user_metadata_t meta) {
    apply {
        // TODO: compute the IPv4 checksum
    }
}

// Instantiate the switch
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
