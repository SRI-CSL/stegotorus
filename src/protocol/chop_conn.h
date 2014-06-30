#ifndef CHOP_CONN_H
#define CHOP_CONN_H

#include "connections.h"

#include "chop_config.h"

#define TRACEPACKETS_TIMESTAMP  log_get_abs_timestamp()

const char passphrase[] =
  "did you buy one of therapist reawaken chemists continually gamma pacifies?";


struct handshake 
{
  uint32_t random;
  uint32_t circuit_id;
  uint32_t cksum;
  uint32_t random2;
};




class chop_conn_t : public conn_t
{

public:
  chop_config_t *config;
  vector<chop_circuit_t *> upstream_circuits;
  steg_t *steg;
  struct evbuffer *recv_pending;
  struct event *must_send_timer;
  bool sent_handshake : 1;
  bool no_more_transmissions : 1;
  uint32_t last_circuit_id;

  CONN_DECLARE_METHODS(chop);

  DISALLOW_COPY_AND_ASSIGN(chop_conn_t);

  int recv_handshake(chop_circuit_t*& ckt);
  int send_block(struct evbuffer *block, chop_circuit_t* upstream);

  void send(int);
  bool must_send_p() const;
  static void must_send_timeout(evutil_socket_t, short, void *arg);
};


#endif
