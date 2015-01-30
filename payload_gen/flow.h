#ifndef _FLOW_H
#define _FLOW_H


#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>

#include "payload_gen.h"

#define NUM_FLOWS 1000
#define NUM_LISTS 1000
typedef unsigned int uint32;
typedef unsigned char uchar;

#define CONN_DATA_REQUEST 1  /* payload packet sent by client */
#define CONN_DATA_REPLY 2  /* payload packet sent by server */

#define RECV_MTU 64000
#define MAX_CHAIN_LEN 4000


#define MSG_INSERTED 1
#define MSG_INVALID 0
#define MSG_SEQ_WRAP -2
#define MSG_DUPLICATE -3
#define CHAIN_TOO_LONG -4
#define MSG_OVERLAP -5
#define CHAIN_HAS_GAPS_OVERLAPS -6
#define CHAIN_EMPTY -7




typedef struct msg {
  u_char *buf;
  ushort len;
  uint32_t seqno;
  struct msg* next_msg;
} msg;

typedef struct flow {
  uint32 src_ip;
  uint32 dst_ip;
  ushort sport;
  ushort dport;
  uint8_t flags;
  uint8_t proto;
  struct timeval change_time;
  int sockfd;
  struct flow* next_flow;
  struct msg* msg_buf_chain;
  int chain_len;
  int msg_len_so_far;
  int  dir;           /* data request or data reply */
  uint32 ack_so_far;  /* what's acknowledged by other end so far */
}flow;

extern flow* flows [NUM_LISTS]; 

flow* has_seen_flow(flow* f);
flow* add_to_flows(flow* f);
flow* reverse_flow(flow* f);
void delete_flow(flow* f);


void free_msg_chain(flow* f);
int has_chain_gaps(flow* f);

int write_msg_chains(flow* f, FILE* file, pentry_header* ph);
int is_valid_http_request(flow* f);
int add_msg_to_flow(flow* f, u_char* buf, uint seq, int len);

#endif
