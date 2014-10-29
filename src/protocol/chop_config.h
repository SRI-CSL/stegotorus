#ifndef CHOP_CONFIG_H
#define CHOP_CONFIG_H

#include <stdint.h>
#include <event2/event.h>
#include <event2/buffer.h>

#include "util.h"


class chop_circuit_t;
class chop_conn_t;

class steg_config_t;

using namespace chop_blk;

typedef unordered_map<uint32_t, chop_circuit_t *> chop_circuit_table;

using std::vector;
using std::make_pair;


class chop_config_t : public config_t
{
public:
  struct evutil_addrinfo *up_address;
  vector<struct evutil_addrinfo *> down_addresses;
  vector<steg_config_t *> steg_targets;
  chop_circuit_table circuits;
  bool trace_packets;
  bool encryption;
  bool retransmit;
    
  CONFIG_DECLARE_METHODS(chop);

  DISALLOW_COPY_AND_ASSIGN(chop_config_t);

};


#endif
