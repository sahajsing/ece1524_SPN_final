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
// const bit<16> DIGEST_TYPE = 16w0x080a;

const bit<4> IPv4 = 4w0x4;

// ARP RELATED CONST VARS
const bit<16> ARP_HTYPE = 0x0001; //Ethernet Hardware type is 1
const bit<16> ARP_PTYPE = IP_TYPE; //Protocol used for ARP is IPV4
const bit<8>  ARP_HLEN  = 6; //Ethernet address size is 6 bytes
const bit<8>  ARP_PLEN  = 4; //IP address size is 4 bytes
const bit<16> ARP_REQ = 1; //Operation 1 is request
const bit<16> ARP_REPLY = 2; //Operation 2 is reply

const port_t CPU_PORT = 1; // port for to control plane

typedef bit<8> digCode_t;
const digCode_t DIG_LOCAL_IP = 1;
const digCode_t DIG_ARP_MISS = 2;
const digCode_t DIG_ARP_REPLY = 3;
const digCode_t DIG_TTL_EXCEEDED = 4;
const digCode_t DIG_NO_ROUTE = 5;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

// standard Ethernet header
header Ethernet_h {
    EthAddr_t dstAddr;
    EthAddr_t srcAddr;
    bit<16> etherType;
}

// TODO: What other headers do you need to add support for?

header ARP_h {
    bit<16> hwType; // 1 for ethernet
    bit<16> protoType; // protocol used in network layer = IPv4
    bit<8> hwLen; //hw address length - 6 for ethernet
    bit<8> protoLen; //proto length = IP address size = 4 bytes
    bit<16> opCode; // operation code -> packet = ARP request (1) or ARP response (2)
    EthAddr_t srcMac;
    IPv4Addr_t srcIP;
    EthAddr_t dstMac; // target hardware address
    IPv4Addr_t dstIP; // target ip address
}

header IPv4_h {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    IPv4Addr_t srcAddr;
    IPv4Addr_t dstAddr;
}
/* Here we define a digest_header type. This header contains information
 * that we want to send to the control-plane. This header should be
 * prepended to all packets sent to the control-plane.
 */
// Digest header
header digest_header_h {
    bit<16>   src_port;
    bit<8>   digest_code;
}

// List of all recognized headers
struct Parsed_packet {
    Ethernet_h ethernet;
    digest_header_h digest;
    ARP_h arp;
    IPv4_h ip;
}

// user defined metadata: can be used to shared information between
// MyParser, MyIngress, and MyDeparser
struct user_metadata_t {
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

// Parser Implementation
parser MyParser(packet_in b,
                 out Parsed_packet p,
                 inout user_metadata_t user_metadata,
                 inout standard_metadata_t standard_metadata) {
    // TODO: Parse any additional headers that you add
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        b.extract(p.ethernet);
        transition select(p.ethernet.etherType){
            ARP_TYPE : parse_arp;
            IP_TYPE : parse_ipv4;
            default : accept;
        }
    }
    
    state parse_arp {
        b.extract(p.arp);
        transition select(p.arp.opCode) {
            ARP_REQ: accept;
            ARP_REPLY: accept;
        }
    }    

    state parse_ipv4 {
        b.extract(p.ip);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout Parsed_packet p, inout user_metadata_t meta) {
    apply {
        // TODO: Verify the IPv4 checksum
        verify_checksum(p.ip.isValid(),
            { p.ip.version,
                p.ip.ihl,
                p.ip.diffserv,
                p.ip.totalLen,
                p.ip.identification,
                p.ip.flags,
                p.ip.fragOffset,
                p.ip.ttl,
                p.ip.protocol,
                p.ip.srcAddr,
                p.ip.dstAddr},
            p.ip.hdrChecksum, HashAlgorithm.csum16);
    }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

// match-action pipeline
control MyIngress(inout Parsed_packet p,
                inout user_metadata_t user_metadata,
                  inout standard_metadata_t standard_metadata) {

    //***** Next states *****//

    IPv4Addr_t next_hop_ip_addr = 0;
    EthAddr_t next_hop_mac_addr = 0;
    port_t dstPort = 0;

    // TODO: Declare your actions and tables
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action send_to_cpu(digCode_t DIG_CODE){
        p.digest.src_port = (bit<16>)standard_metadata.ingress_port; // source port is ingress port packet arrived on
        standard_metadata.egress_spec = CPU_PORT; // send to control plane
        p.digest.digest_code = DIG_CODE;
    }

    //*****  LAYER 3 *****// 

    action set_output_port(port_t port) {
        standard_metadata.egress_spec = port;
    }

    action ipv4_forward(port_t port, IPv4Addr_t next) {
        standard_metadata.egress_spec = port;
        p.ip.dstAddr = next;
    }

    // TODO: Is this what the routing table is supposed to look like?
    
    table routing_table {
        key = {
            p.ip.dstAddr: ternary; // ternary?
        }
        actions = {
            ipv4_forward;
            NoAction;
        }
        size = 64;
        default_action = NoAction();
    }


    table local_ip_table {
        key = {
            p.ip.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            send_to_cpu;
            NoAction; // hit or miss
        }
        size = 64;
        default_action = NoAction();
    }

    //***** LAYER 2 *****//

    action arp_match(EthAddr_t dstAddr) {
        p.arp.opCode = ARP_REPLY; // update op code, request to reply
        p.arp.dstMac = p.arp.srcMac; // reply ARP b destination = source addr
        p.arp.srcMac = dstAddr; // destination MAC address from request 
        p.arp.srcIP = p.arp.dstIP; //reply packet destination IP addr = request source IP addr

        // ethernet header updates
        p.ethernet.dstAddr = p.ethernet.srcAddr;
        p.ethernet.srcAddr = dstAddr;

        // sending back to same port 
        standard_metadata.egress_spec = standard_metadata.ingress_port;

    }

    table arp_cache_table {
        key = {
            p.arp.dstIP : exact; // destination IP addr = key for finding matching MAC addr
        }
        actions = {
            arp_match;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    apply {
        // TODO: Define your control flow

        if (p.ip.isValid()) {
            if (p.ip.ttl <=1) {
                send_to_cpu(DIG_TTL_EXCEEDED);
                drop();
            } else {
                p.ip.ttl = p.ip.ttl-1;
            }

            if (!local_ip_table.apply().hit) {
                if(!routing_table.apply().hit){
                    send_to_cpu(DIG_NO_ROUTE);
                }
                else if (!arp_cache_table.apply().hit){
                    send_to_cpu(DIG_ARP_MISS);
                }
            }

            if (p.arp.isValid() && p.arp.opCode == ARP_REQ) {
                send_to_cpu(DIG_ARP_REPLY);
            }
        }

        // if (p.ip.isValid()) {
        //     if (!local_ip_table.apply().hit) {
        //         // send_to_cpu(DIG_LOCAL_IP); // if address found in local ip table --> sent to CP
        //         if (!routing_table.apply().hit){
        //             send_to_cpu(DIG_NO_ROUTE);
        //         }
        //     }
        //     else {
        //         if(!arp_cache_table.apply().hit) {
        //             send_to_cpu(DIG_ARP_MISS); // check if no ARP match in local ARP Cache table
        //         }
        //         else {
        //             p.ip.ttl = p.ip.ttl -1;
        //             if (p.ip.ttl==0) {
        //                 send_to_cpu(DIG_TTL_EXCEEDED);
        //             }
        //         }
        //     }
        // }

        // else if(p.arp.isValid()) {
        //     if (p.arp.opCode == ARP_REQ) {
        //         send_to_cpu(DIG_ARP_REPLY);
        //     }
        // }
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

// Deparser Implementation
control MyDeparser(packet_out b,
                    in Parsed_packet p) {
    apply {
        // TODO: Emit other headers you've defined
        b.emit(p.digest);
        b.emit(p.ethernet);
        b.emit(p.ip);
        b.emit(p.arp);
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout Parsed_packet p,
                 inout user_metadata_t meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout Parsed_packet p, inout user_metadata_t meta) {
    apply {
        // TODO: compute the IPv4 checksum
        update_checksum(
            p.ip.isValid(),
            { p.ip.version,
              p.ip.ihl,
              p.ip.diffserv,
              p.ip.totalLen,
              p.ip.identification,
              p.ip.flags,
              p.ip.fragOffset,
              p.ip.ttl,
              p.ip.protocol,
              p.ip.srcAddr,
              p.ip.dstAddr },
            p.ip.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

// Instantiate the switch
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
