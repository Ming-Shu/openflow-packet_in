#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openflow_1_3.h"

int read_packet_in_match(struct ofp_packet_in *packet_in,enum oxm_ofb_match_fields field);
void modify_packet_in_match(struct ofp_packet_in **packet_in,enum oxm_ofb_match_fields field,int value);
void packet_in_handle(char* buffer,int buf_len,int cntl_sockfd);

void mask_PacketIn_match(struct ofp_packet_in ** ppacket_in,struct ofp_match* refer,enum oxm_ofb_match_fields field);
