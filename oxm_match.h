#include "openflow_1_3.h"

/* Components of a OXM TLV header. */
#define OXM_HEADER__(CLASS, FIELD, HASMASK, LENGTH) \
    (((CLASS) << 16) | ((FIELD) << 9) | ((HASMASK) << 8) | (LENGTH))
#define OXM_HEADER(CLASS, FIELD, LENGTH) \
    OXM_HEADER__(CLASS, FIELD, 0, LENGTH)

#define OXM_HEADER_W(CLASS, FIELD, LENGTH) \
    OXM_HEADER__(CLASS, FIELD, 1, (LENGTH) * 2)
#define OXM_CLASS(HEADER) ((HEADER) >> 16)
#define OXM_FIELD(HEADER) (((HEADER) >> 9) & 0x7f)
#define OXM_TYPE(HEADER) (((HEADER) >> 9) & 0x7fffff)
#define OXM_HASMASK(HEADER) (((HEADER) >> 8) & 1)
#define OXM_LENGTH(HEADER) ((HEADER) & 0xff)

#define OXM_MAKE_WILD_HEADER(HEADER) \
        OXM_HEADER_W(OXM_CLASS(HEADER), OXM_FIELD(HEADER), OXM_LENGTH(HEADER))

/* OXM Class IDs.
 * The high order bit differentiate reserved classes from member classes.
 * Classes 0x0000 to 0x7FFF are member classes, allocated by ONF.
 * Classes 0x8000 to 0xFFFE are reserved classes, reserved for standardisation.
 */

/* Get the padding needed for some structs */
#define OFP_MATCH_OXM_PADDING(length) \
    ((length + 7)/8*8 - length)
#define OFP_ACTION_SET_FIELD_OXM_PADDING(oxm_len) \
    (((oxm_len + 4) + 7)/8*8 - (oxm_len + 4))

/* Extract fields from an oxm_header */

#define UNPACK_OXM_TLV(TLV_1,TLV_2,TLV_3,TLV_4) \
    (((TLV_1) << 24) | ((TLV_2) << 16) | ((TLV_3) << 8) | (TLV_4))



#define UNPACK_OXM_TLV_PAYLOAD_8_BYTE(PAD_1,PAD_2,PAD_3,PAD_4,PAD_5,PAD_6,PAD_7,PAD_8) \
   (((PAD_1) << 56) | ((PAD_2) << 48) | ((PAD_3) << 40) | ((PAD_4) << 32) | ((PAD_5) << 24) |((PAD_6) << 16) | ((PAD_7) << 8) |(PAD_8))

#define UNPACK_OXM_TLV_PAYLOAD_6_BYTE(PAD_1,PAD_2,PAD_3,PAD_4,PAD_5,PAD_6) \
   (((PAD_1) << 40) | ((PAD_2) << 32) | ((PAD_3) << 24) |((PAD_4) << 16) | ((PAD_5) << 8) |(PAD_6))

#define UNPACK_OXM_TLV_PAYLOAD_4_BYTE(PAD_1,PAD_2,PAD_3,PAD_4) \
   (((PAD_1) << 24) |((PAD_2) << 16) | ((PAD_3) << 8) |(PAD_4))

#define UNPACK_OXM_TLV_PAYLOAD_2_BYTE(PAD_1,PAD_2) \
   (((PAD_1) << 8) |(PAD_2))

/*assign a match_fiele_vlan */
#define PACK_OXM_PAYLOAD(TYPE) \
   (TYPE << 8)	

#define PACK_OXM_TLV(HEADER,TYPE,VALUE) \
   (HEADER<<(PAD_LENGTH*8) | TYPE<<16 | VALUE)	

/* ## ------------------------------- ## */
/* ## OpenFlow compatible fields. ## */
/* ## ------------------------------- ## */

/* Physical or virtual port on which the packet was received.
 *
 * Prereqs: None.
 *
 * Format: 16-bit integer. */
#define    OXM_OF_IN_PORT      OXM_HEADER    (0x8000, 0, 4)


/* Physical port on which the packet was received.
 *
 * Prereqs: None.
 *
 * Format: 32-bit integer. */
#define    OXM_OF_IN_PHY_PORT      OXM_HEADER    (0x8000, 1, 4)

/* Metadata passed btw tables. */
#define OXM_OF_METADATA OXM_HEADER     (0x8000, 2, 8)
#define OXM_OF_METADATA_W OXM_HEADER_W (0x8000, 2, 8)

/* Ethernet destination address.*/
#define    OXM_OF_ETH_DST   OXM_HEADER  (0x8000,3,6) 
#define    OXM_OF_ETH_DST_W OXM_HEADER_W(0x8000,3,6) 

/* Ethernet source address.*/
#define    OXM_OF_ETH_SRC   OXM_HEADER  (0x8000, 4,6)
#define    OXM_OF_ETH_SRC_W OXM_HEADER_W(0x8000,4,6) 

/* Ethernet frame type. */
#define    OXM_OF_ETH_TYPE     OXM_HEADER    (0x8000, 5, 2)

/* VLAN id. */
#define    OXM_OF_VLAN_VID	OXM_HEADER(0x8000, 6, 2)
#define    OXM_OF_VLAN_VID_W OXM_HEADER_W  (0x8000, 6, 2)

 /* VLAN priority. */
#define    OXM_OF_VLAN_PCP   OXM_HEADER  (0x8000, 7, 1)


/* IP ToS (DSCP field, 6 bits). */
#define    OXM_OF_IP_DSCP      OXM_HEADER    (0x8000, 8, 1)

/* IP ECN */
#define    OXM_OF_IP_ECN      OXM_HEADER    (0x8000, 9, 1)

/* IP protocol. */
#define    OXM_OF_IP_PROTO   OXM_HEADER  (0x8000, 10, 1) 

 /* IP source address. */
#define    OXM_OF_IPV4_SRC      OXM_HEADER  (0x8000,11, 4)
#define    OXM_OF_IPV4_SRC_W  OXM_HEADER_W  (0x8000,11, 4) 

/* IP destination address. */
#define    OXM_OF_IPV4_DST     OXM_HEADER  (0x8000,12 , 4) 
#define    OXM_OF_IPV4_DST_W     OXM_HEADER_W  (0x8000,12 , 4) 

/* TCP source port. */
#define    OXM_OF_TCP_SRC      OXM_HEADER  (0x8000, 13, 2)

 /* TCP destination port. */ 
#define    OXM_OF_TCP_DST    OXM_HEADER    (0x8000, 14, 2)

/* UDP source port. */
#define    OXM_OF_UDP_SRC      OXM_HEADER  (0x8000, 15, 2)

 /* UDP destination port. */ 
#define    OXM_OF_UDP_DST    OXM_HEADER    (0x8000, 16, 2)

/* SCTP source port. */
#define    OXM_OF_SCTP_SRC      OXM_HEADER  (0x8000, 17, 2)

 /* SCTP destination port. */ 
#define    OXM_OF_SCTP_DST    OXM_HEADER    (0x8000, 18, 2)

/* ICMPv4 type. */
#define    OXM_OF_ICMPV4_TYPE   OXM_HEADER  (0x8000, 19, 1) 

/* ICMPv4 code. */
#define    OXM_OF_ICMPV4_CODE   OXM_HEADER  (0x8000, 20, 1)

 /* ARP operation code. */
#define    OXM_OF_ARP_OP      OXM_HEADER  (0x8000,21, 2)

 /* IPv4 source address of ARP. */
#define    OXM_OF_ARP_SPA      OXM_HEADER  (0x8000,22, 4)
#define    OXM_OF_ARP_SPA_W  OXM_HEADER_W  (0x8000,22, 4) 

/* IPv4 destination address of ARP. */
#define    OXM_OF_ARP_TPA     OXM_HEADER    (0x8000,23 , 4) 
#define    OXM_OF_ARP_TPA_W   OXM_HEADER_W  (0x8000,23 , 4) 

/* ARP Ethernet destination address.*/
#define    OXM_OF_ARP_SHA   OXM_HEADER  (0x8000,24,6) 
#define    OXM_OF_ARP_SHA_W OXM_HEADER_W(0x8000,24,6) 

/* ARP Ethernet source address.*/
#define    OXM_OF_ARP_THA   OXM_HEADER  (0x8000, 25,6)
#define    OXM_OF_ARP_THA_W OXM_HEADER_W(0x8000,25,6) 

/* IPv6 source address */
#define OXM_OF_IPV6_SRC OXM_HEADER (0x8000, 26, 16)
#define OXM_OF_IPV6_SRC_W OXM_HEADER_W(0x8000, 26, 16)

/* IPv6 destination address*/
#define OXM_OF_IPV6_DST   OXM_HEADER (0x8000, 27, 16) 
#define OXM_OF_IPV6_DST_W OXM_HEADER_W(0x8000, 27, 16)

/* IPv6 flow label*/
#define OXM_OF_IPV6_FLABEL   OXM_HEADER (0x8000, 28, 4)
#define OXM_OF_IPV6_FLABEL_W OXM_HEADER_W (0x8000, 28, 4)

/* ICMPv6 message type field */
#define OXM_OF_ICMPV6_TYPE OXM_HEADER (0x8000, 29, 1) 

/* ICMPv6 type code */
#define OXM_OF_ICMPV6_CODE OXM_HEADER (0x8000, 30, 1) 

/* IPv6 nd target*/
#define OXM_OF_IPV6_ND_TARGET   OXM_HEADER (0x8000, 31, 16) 

/* IPv6 nd target*/
#define OXM_OF_IPV6_ND_SLL  OXM_HEADER (0x8000, 32, 6)

/* IPv6 dnd target*/
#define OXM_OF_IPV6_ND_TLL   OXM_HEADER (0x8000, 33, 6)  

/* MPLS label. */
#define OXM_OF_MPLS_LABEL OXM_HEADER (0x8000, 34, 4)

/* MPLS TC. */
#define OXM_OF_MPLS_TC OXM_HEADER     (0x8000, 35, 1)

#define OXM_OF_MPLS_BOS OXM_HEADER      (0x8000, 36, 1)

#define OXM_OF_PBB_ISID OXM_HEADER      (0x8000, 37, 4)
#define OXM_OF_PBB_ISID_W OXM_HEADER_W  (0x8000, 37, 4)

#define OXM_OF_TUNNEL_ID OXM_HEADER     (0x8000, 38, 8)
#define OXM_OF_TUNNEL_ID_W OXM_HEADER_W (0x8000, 38, 8)

#define OXM_OF_IPV6_EXTHDR  OXM_HEADER      (0x8000, 39, 2)
#define OXM_OF_IPV6_EXTHDR_W  OXM_HEADER_W  (0x8000, 39, 2)

/* ## ------------------------------- ## */
/* ## IPv6 compatible fields. ## */
/* ## ------------------------------- ## */


/* Traffic Class */
#define OXM_OF_IPV6_TC OXM_HEADER (0x0002, 5, 1)
#define OXM_OF_IPV6_TC_W OXM_HEADER_W (0x0002, 5, 1)

/* IPv6 Hop-by-Hop EH ID*/
#define OXM_OF_IPV6_HBH_ID OXM_HEADER (0x0002, 8, 1)
#define OXM_OF_IPV6_HBH_ID_W OXM_HEADER_W (0x0002, 8, 1)  

#define OXM_OF_IPV6_HBH_OPT_CODE OXM_HEADER (0x0002, 9, 1) 

#define OXM_OF_IPV6_HBH_OPT_VALUE OXM_HEADER_VL (0x0002, 10) 

/* IPv6 Destination Option EH ID*/
#define OXM_OF_IPV6_DOH_ID OXM_HEADER (0x0002, 16, 1)
#define OXM_OF_IPV6_DOH_ID_W OXM_HEADER_W (0x0002, 16, 1)

#define OXM_OF_IPV6_DOH_OPT_CODE OXM_HEADER (0x0002, 17, 1)

#define OXM_OF_IPV6_DOH_OPT_VALUE OXM_HEADER_VL (0x0002, 18)


/* IPv6 Routing EH ID*/ 
#define OXM_OF_IPV6_RH_ID OXM_HEADER (0x0002, 24, 1)
#define OXM_OF_IPV6_RH_ID_W OXM_HEADER_W (0x0002, 24, 1)

#define OXM_OF_IPV6_RH_ADDRESS OXM_HEADER (0x0002, 25, 16)

/* IPv6 Fragmentation EH ID*/
#define OXM_OF_IPV6_FH_ID OXM_HEADER (0x0002, 32, 1)
#define OXM_OF_IPV6_FH_ID_W OXM_HEADER_W (0x0002, 32, 1)

/* IPv6 Authentication EH ID*/ 
#define OXM_OF_IPV6_AH_ID OXM_HEADER (0x0002, 40, 1)
#define OXM_OF_IPV6_AH_ID_W OXM_HEADER_W (0x0002, 40, 1)

/* IPv6 Encapsulating Security Payload */ 
#define OXM_OF_IPV6_ESP_ID OXM_HEADER (0x0002, 48, 1) 

/* IPv6 Mobility EH */
#define OXM_OF_IPV6_MH_ID OXM_HEADER (0x0002, 56, 1) 

/* ## ------------------------------- ## */
/* ## TTL fields. ## */
/* ## ------------------------------- ## */

/* MPLS TTL */
#define OXM_OF_MPLS_TTL OXM_HEADER (0x0002, 80, 4)

/* IPv4 TTL */
#define OXM_OF_IPV4_TTL OXM_HEADER (0x0002, 81, 1)

