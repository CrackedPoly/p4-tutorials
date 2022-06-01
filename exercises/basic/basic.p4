/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;  /* define the length of mac address*/
typedef bit<32> ip4Addr_t;  /* define the length of ipv4 address */

/* a standard ethernet header */
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
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
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

/*
    const -> fixed identifiers
    typedef -> some frequently used bit widths
    header -> some protocol headers
    struct -> packet headers, custom metadata and standard metadata
*/

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

/* parser describes a state machine to define whether a packet to accept or
    reject. MyParser takes in a packet_in, three structs including headers, 
    matadata(the 2 we defined before) and standard_metadata_t(the builtin
    intermediate struct of P4 runtime). */
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    /* always begin with a `start` state */
    state start {
        /* go to parse ethernet header */
        transition parse_ethernet;
    }

    state parse_ethernet {
        /* extract the ethernet header, if correct, mark the header valid */
        packet.extract(hdr.ethernet);
        /* goto a `switch` branch parser */
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

/* MyIngress is the Ingress match+action stage in the model. Unlike MyParser, 
    we don't need to write a packet_in in the parameters, because at the stage
    we only need to manipulate headers. */
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        /* mark the packet as drop automatically. */
        mark_to_drop(standard_metadata);
    }

    /* The action params in the table entry of MyIngress.ipv4_forward must match
        the declaration(macAddr_t 48bit, egressSpec_t 9bit). */
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        /* match condition */
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            /* how do ipv4_forward know the  */
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            /* prerequisite to determine whether to execute update_checksum */
            hdr.ipv4.isValid(),
            /* checksum fields */
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            /* where to write */
            hdr.ipv4.hdrChecksum,
            /* whick hash to use */
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

/* Like MyParser, this Deparser takes in packet_out and headers. During this
    stage, physical switch will assemble the real packet with payload and headers,
    so there won't be standard_metadata_t and any custom metadata. */
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /* The order matters. Must follow the sequence of a actual ethernet frame. */
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
