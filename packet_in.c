#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include"channel_communication.h"
#include "ofp_type_message.h"
#include "oxm_match.h"
#include "flow_mod.h"
#include "proxy_table.h"
#include "packet_in.h"

int read_packet_in_match(struct ofp_packet_in *packet_in,enum oxm_ofb_match_fields field)
{
  int value,match_len;
  uint8_t *pOxm_tlv;
	
	pOxm_tlv = packet_in->match.oxm_fields;
	match_len=htons(packet_in->match.length)-4;//The size of type & len is 4 byte 
	while(OXM_FIELD(UNPACK_OXM_TLV(*pOxm_tlv,*(pOxm_tlv+1),*(pOxm_tlv+2),*(pOxm_tlv+3)))!=field && match_len>0)
	{
		match_len-=(OXM_LENGTH( UNPACK_OXM_TLV(*pOxm_tlv,*(pOxm_tlv+1),*(pOxm_tlv+2),*(pOxm_tlv+3)))+4);	
		pOxm_tlv+=(OXM_LENGTH(UNPACK_OXM_TLV(*pOxm_tlv,*(pOxm_tlv+1),*(pOxm_tlv+2),*(pOxm_tlv+3)))+4);
	}

	if(OXM_FIELD(UNPACK_OXM_TLV(*pOxm_tlv,*(pOxm_tlv+1),*(pOxm_tlv+2),*(pOxm_tlv+3)))==field)
		value = read_payload(pOxm_tlv+4,(OXM_LENGTH(UNPACK_OXM_TLV(*pOxm_tlv,*(pOxm_tlv+1),*(pOxm_tlv+2),*(pOxm_tlv+3)))));
	else
		value =-1;
  return value;	
}//read_packet_in_match


void modify_packet_in_match(struct ofp_packet_in **packet_in,enum oxm_ofb_match_fields field,int value)
{
  struct ofp_packet_in *p;
  int match_len;
  uint32_t *w_oxm_tlv,oxm_type;
  uint16_t *w_2byte_oxm_tlv; 
  uint8_t *pOxm_tlv;

	p = *packet_in;
	pOxm_tlv = &p->match.oxm_fields;
	match_len=htons(p->match.length)-4;//The size of type & len is 4 byte 
	while(OXM_FIELD(UNPACK_OXM_TLV(*pOxm_tlv,*(pOxm_tlv+1),*(pOxm_tlv+2),*(pOxm_tlv+3)))!=field && match_len>0)
	{
		match_len-=(OXM_LENGTH( UNPACK_OXM_TLV(*pOxm_tlv,*(pOxm_tlv+1),*(pOxm_tlv+2),*(pOxm_tlv+3)))+4);	
		pOxm_tlv+=(OXM_LENGTH(UNPACK_OXM_TLV(*pOxm_tlv,*(pOxm_tlv+1),*(pOxm_tlv+2),*(pOxm_tlv+3)))+4);
    
	}

	  switch(field) {
		case OFPXMT_OFB_IN_PORT:{
				oxm_type = OXM_OF_IN_PORT;
				printf("case OFPXMT_OFB_IN_PORT\n" );
			 break; 
		}
		case OFPXMT_OFB_VLAN_VID:{
 				oxm_type = OXM_OF_VLAN_VID;
				printf("case  OFPXMT_OFB_VLAN_VID\n" );
			 break; 
		}
		default:{
			printf("The oxm_type is not exist\n" );
			break;
		}
	  }//switch
     
	if(OXM_FIELD(UNPACK_OXM_TLV(*pOxm_tlv,*(pOxm_tlv+1),*(pOxm_tlv+2),*(pOxm_tlv+3)))==field)
	{
          
	  switch(oxm_type) {
		case OXM_OF_IN_PORT:{
			 w_oxm_tlv = pOxm_tlv;
			*w_oxm_tlv =  ntohl(oxm_type);
			*(w_oxm_tlv+1)=ntohl(value);
			printf("value:%d\n\n",value);
			 break; 
		}
		case OXM_OF_VLAN_VID:{
 			 w_oxm_tlv = pOxm_tlv;
 			*w_oxm_tlv =  ntohl(oxm_type);
  			 w_2byte_oxm_tlv= (w_oxm_tlv+1);
 			*(w_2byte_oxm_tlv)=ntohs(value);
			printf("value:%d\n\n",value);
			 break; 
		}
		default:{
			printf("The oxm_type is not exist\n" );
			break;
		}
	  }//switch
	}//if  
		
}// modify_packet_in_match

void mask_PacketIn_match(struct ofp_packet_in ** ppacket_in,struct ofp_match* refer,enum oxm_ofb_match_fields field)
{
printf("---------------mask_PacketIn_match------------\n\n");
     //struct ofp_match* p;
     struct ofp_packet_in* p; 
     int match_len;
     /*uint32_t *w_oxm_tlv,*r_oxm_tlv;
     uint16_t *w_2byte_OxmTlv,r_2byte_OxmTlv; */
     uint8_t *pOxm_tlv,*rOxm_tlv;
     p = *ppacket_in;
     p->match.type = refer->type;
     p->match.length = refer->length;
     pOxm_tlv = &p->match.oxm_fields;
     rOxm_tlv = &refer->oxm_fields; 
     
     printf("refer->length:%d\n",htons(refer->length));
     printf("p->match.length:%d\n\n",htons(p->match.length));		
     match_len=htons(refer->length)-4;//The size of type & len is 4 byte 
     while(match_len>0)
	 {
 	//oxm_match_printf(rOxm_tlv);
        if(OXM_FIELD(UNPACK_OXM_TLV(*rOxm_tlv,*(rOxm_tlv+1),*(rOxm_tlv+2),*(rOxm_tlv+3)))==field){
		p->match.length = htons(htons(refer->length)-OXM_LENGTH(UNPACK_OXM_TLV(*rOxm_tlv,*(rOxm_tlv+1),*(rOxm_tlv+2),*(rOxm_tlv+3)))-4);
		
		printf("find field refer->length:%d\n\n",htons(refer->length));
	     	printf("find field p->match.length:%d\n\n",htons(p->match.length));
	}else{
          	 memcpy(pOxm_tlv,rOxm_tlv,(OXM_LENGTH(UNPACK_OXM_TLV(*rOxm_tlv,*(rOxm_tlv+1),*(rOxm_tlv+2),*(rOxm_tlv+3)))+4)); 
	
	oxm_match_printf(pOxm_tlv);                                                                                       
       	}//else    
		match_len-=(OXM_LENGTH(UNPACK_OXM_TLV(*rOxm_tlv,*(rOxm_tlv+1),*(rOxm_tlv+2),*(rOxm_tlv+3)))+4);	
		pOxm_tlv+=(OXM_LENGTH(UNPACK_OXM_TLV(*pOxm_tlv,*(pOxm_tlv+1),*(pOxm_tlv+2),*(pOxm_tlv+3)))+4);
		rOxm_tlv+=(OXM_LENGTH(UNPACK_OXM_TLV(*rOxm_tlv,*(rOxm_tlv+1),*(rOxm_tlv+2),*(rOxm_tlv+3)))+4);
	 }
     printf("mask_PacketIn_match.length:%d\n\n",htons(p->match.length));
}//mask_PacketIn_match

void packet_in_handle(char* buffer,int buf_len,int cntl_sockfd)
{
  printf("------------------Staring handle 'packet_in' message from switch-------------\n\n");
  int in_port,vlan,packet_in_length;
  struct ofp_packet_in *p,*c;
  //struct ofp_match* pMatch;
  p = (struct ofp_packet_in*)buffer;

  packet_in_length = htons(p->header.length);
  in_port = read_packet_in_match(p,OFPXMT_OFB_IN_PORT);	
  printf("in_port :%d\n",in_port);

  if(in_port>OF_OLT_CONNT_NUM )
  {
	printf("\nin_port>OF_OLT_CONNT_NUM .....\n\n");
   	in_port = of_virtual_port(in_port);
	modify_packet_in_match(&p,OFPXMT_OFB_IN_PORT,in_port);
	send(cntl_sockfd,p,packet_in_length,0);
  }else{
	in_port = p->table_id-1;
	printf("in_port :%d\n",in_port);
	p->table_id=0; 
	modify_packet_in_match(&p,OFPXMT_OFB_IN_PORT,in_port);
	send(cntl_sockfd,p,packet_in_length,0);
  }	
}//packet_in_handle*/

/*
void packet_in_handle(char* buffer,int buf_len,int cntl_sockfd)
{
  printf("------------------Staring handle 'packet_in' message from switch-------------\n\n");
  int in_port,vlan,packet_in_length;
  struct ofp_packet_in *p,*c;
  //struct ofp_match* pMatch;
  p = (struct ofp_packet_in*)buffer;	

  packet_in_length = htons(p->header.length);
  in_port = read_packet_in_match(p,OFPXMT_OFB_IN_PORT);	
  printf("in_port :%d\n",in_port);

  if(in_port>OF_OLT_CONNT_NUM )
  {
	printf("\nin_port>OF_OLT_CONNT_NUM .....\n\n");
   	in_port = of_virtual_port(in_port);
	modify_packet_in_match(&p,OFPXMT_OFB_IN_PORT,in_port);
	send(cntl_sockfd,p,packet_in_length,0);
  }else{
    char *creat_packet_in;    
    creat_packet_in=(char*)malloc(buf_len);
    memset(creat_packet_in, 0,buf_len);
    c = (struct ofp_packet_in*)creat_packet_in;
    c->header.version= p->header.version ;
    c->header.type	 = p->header.type;
    //c->header.length = p->header.length;
    c->header.xid	 = p->header.xid; 
    c->buffer_id     = p->buffer_id;
    //c->total_len     = p->total_len;
    c->reason        = p->reason;
    c->table_id      = 0;//p->table_id; 
    c->cookie        = p->cookie;   	
  	vlan = read_packet_in_match(p,OFPXMT_OFB_VLAN_VID);
   	printf("vlan :%d\n",vlan);	
	in_port = vlan-1;
	printf("in_port :%d\n",in_port);
    modify_packet_in_match(&p,OFPXMT_OFB_IN_PORT,in_port);
    printf("modify inport:%d\n",read_packet_in_match(p,OFPXMT_OFB_IN_PORT));		
    //pMatch = &c->match;
    mask_PacketIn_match(&c,&p->match,OFPXMT_OFB_VLAN_VID);
    mask_PacketIn_match(&c,&c->match,OFPXMT_OFB_VLAN_PCP);	
   
    c->header.length = htons(sizeof(struct ofp_packet_in)-sizeof(struct ofp_match)+htons(c->match.length)+2+OFP_MATCH_OXM_PADDING(htons(c->match.length)));  

    c->total_len     =	htons(htons(p->total_len)-OFP_MATCH_OXM_PADDING(htons(p->match.length))+OFP_MATCH_OXM_PADDING(htons(c->match.length)));

    printf("c->total_len:(%d) = c->header.length:(%d) - sizeof(struct ofp_packet_in:(%d),OFP_MATCH_OXM_PADDING(htons(c->match.length)):%d\n\n",htons(c->total_len),htons(sizeof(struct ofp_packet_in)),sizeof(struct ofp_packet_in),OFP_MATCH_OXM_PADDING(htons(c->match.length)));	
    printf("Before_header.length:%d\n,match.length:%d\n,total_len:%d\n\n",htons(p->header.length),htons(p->match.length),htons(p->total_len));		
    printf("Modify_header.length:%d\n,match.length:%d\n,total_len:%d\n\n",htons(c->header.length),htons(c->match.length),htons(c->total_len));	
 
    send(cntl_sockfd,c,htons(c->header.length),0);
  }	
	
}//packet_in_handle*/
