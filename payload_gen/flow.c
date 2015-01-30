#include "flow.h"

flow* flows [NUM_LISTS]; 


int hash_flow(flow* f) {
  return (f->src_ip + f->dst_ip + f->sport + f->dport) % NUM_LISTS;
}


void reset_flow(flow* f) {
  bzero(f, sizeof(flow));
}



/* returns 0 or 1 */
int flow_compare(flow* f1, flow* f2) {
  if (f1->src_ip == f2->src_ip && f1->dst_ip == f2->dst_ip
      && f1->sport == f2->sport && f1->dport == f2->dport)
    return 1;
  return 0;

}



/* returns 0 or 1 */
int is_null_flow(flow* f) {
  if (f->src_ip == 0 && f->dst_ip == 0 && f->sport == 0 && f->dport == 0)
    return 1;
  return 0;
}




void delete_flow(flow* f) {
  int hval = hash_flow(f);
  flow* cflow = flows[hval];
  flow* parent = cflow;
  
  if (cflow == NULL) {
    fprintf(stderr, "flow not found\n");
    return;
  } 

  // no parent
  if (flow_compare(cflow, f)) {
    flows[hval] = cflow->next_flow;
    free(cflow);
    return;
  }


  cflow = cflow->next_flow;

  while (cflow != NULL) {
    if (flow_compare(cflow, f)) {
      parent->next_flow = cflow->next_flow;
      free(cflow);
      return;
    }
    parent = cflow;
    cflow = cflow->next_flow;
  }
  
  fprintf(stderr, "flow not found...\n");
}


flow* add_to_flows(flow* f) {
  int hval = hash_flow(f);
 
  flow* cflow = flows[hval];
    
  if (cflow == NULL) {
    cflow = (flow*) malloc(sizeof(flow));
    memcpy(cflow, f, sizeof(flow));
    cflow->next_flow = NULL;
    flows[hval] = cflow;
    return cflow;
  } 
  else {
    // add flow to the beginning of the chain
    flow* old_flow = (flow*) malloc(sizeof(flow));
    memcpy(old_flow, cflow, sizeof(flow));    
    memcpy(cflow, f, sizeof(flow));
    cflow->next_flow = old_flow;
  }
  return cflow;
}




flow* has_seen_flow(flow* f) {
  int hval = hash_flow(f);

  flow* cflow = flows[hval];

  while (cflow != NULL) {
    if (flow_compare(cflow, f)) 
      return cflow;
    cflow = cflow->next_flow;
  }

  return NULL;
  
}

flow* reverse_flow(flow* f) {
  uint32_t tmp_ip;
  ushort tmp_port;

  tmp_ip = f->src_ip;
  f->src_ip = f->dst_ip;
  f->dst_ip = tmp_ip;

  tmp_port = f->sport;
  f->sport = f->dport;
  f->dport = tmp_port;
  return f;
}

void print_flow(flow* f) {
  struct in_addr addr;
  addr.s_addr = f->src_ip;
  fprintf(stderr, "\n<Flow client = \"%s\" %d ", inet_ntoa(addr), f->sport);
  addr.s_addr = f->dst_ip;
  fprintf(stderr, " server = \"%s\" %d>\n", inet_ntoa(addr), f->dport); 
}




int is_flow_expired(flow* f, int timer) {
  if (timer > f->change_time.tv_sec && 
      timer - f->change_time.tv_sec > 3600)
    return 1;

  return 0;
}

