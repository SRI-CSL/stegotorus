#ifndef _CHECKSUM_H
#define _CHECKSUM_H

#include "read_pcap.h"
extern "C" {
#include <libnet.h>
}

inline int verify_ip_checksum(struct ip* iph) {
  int check = iph->ip_sum;
  int len= ntohs(iph->ip_len) - sizeof(struct ip);

  if (libnet_do_checksum((u_char*) iph, IPPROTO_IP, IP_H) == -1) {
    fprintf(stderr, "do checksum verification failed 1\n");
    return 0;
  }

  if (check != iph->ip_sum) {
    fprintf(stderr, "ip checksum verification failed 2\n");
    return 0;
  }

  switch(iph->ip_p) {
  case IPPROTO_TCP: {
    struct tcphdr* tcph = (struct tcphdr*) ((u_char*) iph + sizeof(struct ip));
    check = tcph->th_sum;
    tcph->th_sum=0; 

    if (libnet_do_checksum((u_char*) iph, IPPROTO_TCP, len) == -1 ) {
      fprintf(stderr, "do TCP checksum verification failed 2\n");
      return 0;
    }

    if (tcph->th_sum != check) {
      fprintf(stderr, "TCP checksum verification failed 2\n");
      return 0;
    }
    break;
  }
  case IPPROTO_UDP: 
    {
    struct udphdr* udph = (struct udphdr*) ((u_char*) iph + sizeof(struct ip));
    check = udph->uh_sum;
    udph->uh_sum=0;

    if (libnet_do_checksum((u_char*) iph, IPPROTO_UDP, len) == -1 ) {
      fprintf(stderr, "do checksum verification failed 2\n");
      return 0;
    }

    if (udph->uh_sum != check) {
      fprintf(stderr, "UDP checksum verification failed 2\n");
      return 0;
    }
    }
  }
  

  return 1;
}

#endif
