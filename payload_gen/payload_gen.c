#include "flow.h"
#include "payload_gen.h"


int errval;
pcap_t* descr;
char dumpfile[100]; 
int dir_flag = 0;
char bp_filter[10000];
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;  
bpf_u_int32 netp;


#define RECV_MTU 64000
// #define PKT_MTU 1400       

#define PORT_HTTP 80

FILE* client_file;
FILE* server_file;
FILE* automata_file;


void usage() {
  fprintf(stdout,"Usage:  [-r dumpfile] \"bpf filter\" \n");
  exit(1);
}



void terminate() {
 
  struct pcap_stat ps;
  
  if (pcap_stats(descr, &ps) < 0) {
    printf("err: pcap stats not supported? \n");
    exit(1); 
  } 

  printf("packets rcvd: %u, packets dropped: %u, interface drops: %u\n",
	 ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);

  exit(1);

}



void write_http_packet(flow* f) {
  pentry_header ph;
  ph.length = htonl(f->msg_len_so_far);
  ph.port = htons(80);

  if (f->dir == CONN_DATA_REQUEST) {
    ph.ptype = htons(TYPE_HTTP_REQUEST);
    if (is_valid_http_request(f)) {
      //      fwrite(&ph, sizeof(ph), 1, client_file);
      //      fwrite(payload, len, 1, client_file);
      write_msg_chains(f, client_file, &ph);
    }
  }
  else {
    ph.ptype = htons(TYPE_HTTP_RESPONSE);
    write_msg_chains(f, server_file, &ph);
    //    fwrite(&ph, sizeof(ph), 1, server_file);
    //    fwrite(payload, len, 1, server_file);
  }

  //  f->current_state = ph.ptype;
}	

void write_packet(flow* f) {
  ushort tport;
  if (f->dir == CONN_DATA_REQUEST)
    tport = f->dport;
  else
    tport = f->sport;

  switch(tport) {
  case PORT_HTTP:
    write_http_packet(f);
  }

}


void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,
		 const u_char* packet) {
 
  struct ether_header *eth = (struct ether_header*) (packet) ;
  int rval;

  if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
    
    struct ip* iph = (struct ip*) (packet + sizeof(struct ether_header));
    struct tcphdr* tcph = (struct tcphdr*) 
	((u_char*)iph + sizeof(struct ip));

    //    fprintf(stderr, "next packet\n");

    
    int len = htons(iph->ip_len) - 4*tcph->th_off - sizeof(struct ip);
    u_char* payload = (u_char*) tcph + 4*tcph->th_off;
    flow f;
    flow* cflow;
    flow* rflow;

    bzero(&f, sizeof(flow));
    f.src_ip = iph->ip_src.s_addr;
    f.dst_ip = iph->ip_dst.s_addr;
    f.sport  = ntohs(tcph->th_sport);
    f.dport  = ntohs(tcph->th_dport);
    f.flags  = tcph->th_flags;
    f.proto  = iph->ip_p;
    f.change_time = pkthdr->ts;
      
    if (tcph->th_flags & TH_SYN && !(tcph->th_flags & TH_ACK)) {
      f.dir = CONN_DATA_REQUEST;
      add_to_flows(&f);
      return;
    }

    else if ((tcph->th_flags & TH_SYN) && (tcph->th_flags & TH_ACK)) {

      	f.dir = CONN_DATA_REPLY;
      	add_to_flows(&f);
	return;

    }


    cflow = has_seen_flow(&f);
    
    if (!cflow) {
      return;
    }    

    rflow = has_seen_flow(reverse_flow(&f));
    
    if (!rflow)
      return;

    rflow->ack_so_far = ntohl(tcph->th_ack);      

    cflow->flags = cflow->flags | tcph->th_flags;


    //    fprintf(stderr, "here %d %d %d\n", len, ntohl(tcph->th_seq), cflow->ack_so_far);
    if (len > 0 && ntohl(tcph->th_seq) >= cflow->ack_so_far) {
      if (rflow->msg_len_so_far > 0) {
	write_packet(rflow);
	free_msg_chain(rflow);
      }

      rval = add_msg_to_flow(cflow, payload, ntohl(tcph->th_seq), len);
          
      if (rval <= 0 && rval !=MSG_DUPLICATE && rval != CHAIN_TOO_LONG) {
	fprintf(stderr, "adding msg to flow failed %d %d\n", rval, len);
      }
      //      else
      //	fprintf(stderr, "added packet\n");

    }

    
    if (cflow->flags & TH_RST || cflow->flags & TH_FIN) {      
      /*      if (cflow->msg_len_so_far > 0) {
	      write_packet(cflow);
	      free_msg_chain(cflow);
	      }
      */

      if (rflow->msg_len_so_far > 0) {
	write_packet(rflow);
	free_msg_chain(rflow);
      }
      return;
    }


  }
}




void handle_pcap_file(char* filename) {
  if (filename != NULL) {
    descr = pcap_open_offline(filename, errbuf);
    
    if(descr == NULL) { 
      printf("pcap_open_offline(): %s\n",errbuf); 
      exit(1); 
    }    
  } 

  
  if(pcap_compile(descr,&fp,bp_filter,1,netp) == -1) { 
    fprintf(stderr,"Error calling pcap_compile on \"%s\"\n", 
	    bp_filter); exit(1); 
  }

  /* set the compiled program as the filter */
  if(pcap_setfilter(descr,&fp) == -1) { 
    fprintf(stderr,"Error setting filter\n"); 
    exit(1); 
  }

  /* main pcap loop */ 
  pcap_loop(descr,-1,my_callback,NULL);
}


void list_files(char* dirname) {
  DIR *dip;
  struct dirent *dit;
  int i=0;
  char buf[150];
 

  if ((dip = opendir(dirname)) == NULL) {
    perror("opendir");
    return;
  }
  
  while ((dit = readdir(dip)) != NULL) {
    i++;
    if (i < 3)
      continue;

    sprintf(buf, "%s/%s", dirname, dit->d_name);
    fprintf(stderr, "%s\n", buf);
    handle_pcap_file(buf);
  }

  if(closedir(dip) == -1) {
    perror("closedir");
    return;
  }
}



void build_state(state* st, StateFlag flg, PacketType type, 
		 int dir, SID id, SID ns) {
  st->id = htonl(id);
  st->flg = htons(flg);
  st->data_type = htons(type);
  st->next_state = htonl(ns);
  st->dir = htonl(dir);

}

void build_port80_automata() {
  state s1;
  state s2;
  state s3;

  build_state(&s1, BEGIN_STATE_FLG, TYPE_HTTP_REQUEST,
	      CONN_DATA_REQUEST, 1, 2);

  build_state(&s2, END_STATE_FLG, TYPE_HTTP_RESPONSE,
	      CONN_DATA_REPLY, 2, 3);

  build_state(&s3, END_STATE_FLG, TYPE_SERVICE_DATA,
	      CONN_DATA_REPLY, 3, NO_NEXT_STATE);

  fwrite(&s1, sizeof(s1), 1, automata_file); 
  fwrite(&s2, sizeof(s2), 1, automata_file); 
  fwrite(&s3, sizeof(s3), 1, automata_file); 
}



int main(int argc,char **argv) { 

  int c;

  client_file = fopen("client.out", "w");
  server_file = fopen("server.out", "w");
  automata_file = fopen("autom.out", "w");
  
  bzero(flows, sizeof(flows));
  build_port80_automata();

  while ((c = getopt (argc, argv, "r:d:")) != -1) {
    switch (c) {
    case 'r':
      strcpy(dumpfile, optarg);
      break;
    case 'd':
      dir_flag = 1;
      strcpy(dumpfile, optarg);
      break;

    default:
      usage();


    }
  }
   

  if (argv[optind] == NULL)
    usage();

  strcpy(bp_filter, argv[optind]);
  
  /* catch ^C print stats and exit */
  (void) signal(SIGTERM, terminate);
  (void) signal(SIGINT, terminate); 
  (void) signal(SIGHUP, terminate);

  if (dir_flag) {
    list_files(dumpfile);
  }
  else
    handle_pcap_file(dumpfile);

  fclose(client_file);
  fclose(server_file);
  fclose(automata_file);

  return 0;
}
