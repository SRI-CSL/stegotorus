/* Copyright 2011, 2012, 2013, 2014 SRI International
 * See LICENSE for other credits and copying information
 */

#include <sstream>
#include <vector>
#include <event2/event.h>
#include <event2/buffer.h>

#include "util.h"
#include "chop_blk.h"
#include "connections.h"
#include "modus_operandi.h"
#include "crypt.h"
#include "protocol.h"
#include "rng.h"
#include "steg.h"
#include "../steg/crypto.h"
#include "chop_config.h"
#include "chop_circuit.h"
#include "chop_conn.h"


#include "chop_circuit.cc"
#include "chop_conn.cc"




/* The chopper is the core StegoTorus protocol implementation.
   For its design, see doc/chopper.txt.  Note that it is still
   being implemented, and may change incompatibly.  */

using std::vector;
using std::make_pair;





// Configuration methods
chop_config_t::chop_config_t() : up_address(NULL), down_addresses(), steg_targets(), circuits(),  trace_packets(false), encryption(true), retransmit(true)
{
  ignore_socks_destination = true;
}

chop_config_t::~chop_config_t()
{
  if (up_address)
    evutil_freeaddrinfo(up_address);
  for (vector<struct evutil_addrinfo *>::iterator i = down_addresses.begin();
       i != down_addresses.end(); i++)
    evutil_freeaddrinfo(*i);

  for (vector<steg_config_t *>::iterator i = steg_targets.begin();
       i != steg_targets.end(); i++)
    delete *i;

  for (chop_circuit_table::iterator i = circuits.begin();
       i != circuits.end(); i++)
    if (i->second)
      delete i->second;

  free((void *)shared_secret);
  free((void *)hostname);
  
}



bool
chop_config_t::is_good(modus_operandi_t &mo)
{
  /* could be improved; but this is a good first sanity check */
  return mo.protocol() == "chop"     &&
    !mo.mode().empty()               &&
    !mo.up_address().empty()         &&
    mo.down_addresses().size() > 0;
}
    
bool
chop_config_t::init(int n_options, const char *const *options, modus_operandi_t &mo)
{
  const char* defport;
  const char* cmode;
  int listen_up;
  int i;

  if (!mo.is_ok() && n_options < 3) {
    log_warn("chop: not enough parameters");
    goto usage;
  }

  if(mo.is_ok() && n_options != 0){
    log_warn("Starting with both a configuration file *and* commandline options is *currently* not supported. Sorry.");
    return false;
  }

  if(!this->is_good(mo) && n_options == 0){
    log_warn("Configuration file not good enough for chop (needs mode, up_address and at least one down_address)! Sorry.");
    return false;
  }

  if(mo.is_ok()){
    cmode = mo.mode().c_str();
  } else {
    cmode = options[0];
  }

  //less adhoc way of passing information down to the steg modules.
  this->mop = &mo;

  //remember the shared_secret once and forall
  this->shared_secret = xstrdup(mo.shared_secret().c_str());

  //remember the hostname once and forall
  this->hostname = xstrdup(mo.hostname().c_str());
  
  
  if (!strcmp(cmode, "client")) {
    defport = "48988"; // bf5c
    mode = LSN_SIMPLE_CLIENT;
    listen_up = 1;
  } else if (!strcmp(cmode, "socks")) {
    defport = "23548"; // 5bf5
    mode = LSN_SOCKS_CLIENT;
    listen_up = 1;
  } else if (!strcmp(cmode, "server")) {
    defport = "11253"; // 2bf5
    mode = LSN_SIMPLE_SERVER;
    listen_up = 0;
  } else
    goto usage;

  
  
  if(mo.is_ok()){
    vector<string> addresses;
    
    up_address = resolve_address_port(mo.up_address().c_str(), 1, listen_up, defport);
    
    if (!up_address) {
      log_warn("chop: invalid up address: %s", options[1]);
      goto usage;
    }

    addresses = mo.down_addresses();

    // the down address in the modus_operandi_t consists of both the address and the steg targets.
    for (i = 0; i < (int)addresses.size(); i++) {
      down_address_t da;
      da.parse(addresses[i]);

      if (da.ok) {
	struct evutil_addrinfo *addr =
	  resolve_address_port(da.ip.c_str(), 1, !listen_up, NULL);
	if (!addr) {
	  log_warn("chop: invalid down address: %s", da.ip.c_str());
	  goto usage;
	}

	down_addresses.push_back(addr);
      	
	if (!steg_is_supported(da.steg.c_str())) {
	  log_warn("chop: steganographer '%s' not supported", da.steg.c_str());
	  goto usage;
	}

	steg_targets.push_back(steg_new(da.steg.c_str(), this));
      
      } else {
        log_warn("chop: invalid down address: %s", addresses[i].c_str());
        goto usage;
      }
    }
    
    if(mo.trace_packets()){
      trace_packets = true;
      log_enable_timestamps();
    }
    
    persist_mode = mo.persist_mode();    
    encryption = !mo.disable_encryption();
    retransmit = !mo.disable_retransmit();

    if(!mo.shared_secret().empty()){
      shared_secret = xstrdup(mo.shared_secret().c_str());
    }
    
    return true;
  } 
  
  while (options[1][0] == '-') {
    if (!strncmp(options[1], "--server-key=", 13)) {
      // accept and ignore (for now) client only
      if (mode == LSN_SIMPLE_SERVER) {
        log_warn("chop: --server-key option is not valid in server mode");
        goto usage;
      }
    } else if (!strcmp(options[1], "--trace-packets")) {
      trace_packets = true;
      log_enable_timestamps();
    } else if (!strcmp(options[1], "--persist-mode")) {
      persist_mode = true;
    } else if (!strcmp(options[1], "--disable-encryption")) {
      encryption = false;
    } else if (!strcmp(options[1], "--disable-retransmit")) {
      retransmit = false;
    } else if (!strncmp(options[1], "--shared-secret=", 16)) {
      shared_secret = xstrdup(&options[1][16]);
      log_debug("shared_secret is '%s'", shared_secret);
    } else {
      log_warn("chop: unrecognized option '%s'", options[1]);
      goto usage;
    }
    options++;
    n_options--;
  }
  
  up_address = resolve_address_port(options[1], 1, listen_up, defport);
    
  if (!up_address) {
    log_warn("chop: invalid up address: %s", options[1]);
    goto usage;
  }
    
  // From here on out, arguments alternate between downstream
  // addresses and steg targets.
  for (i = 2; i < n_options; i++) {
    struct evutil_addrinfo *addr = resolve_address_port(options[i], 1, !listen_up, NULL);

    if (!addr) {
      log_warn("chop: invalid down address: %s", options[i]);
      goto usage;
    }

    down_addresses.push_back(addr);      
    i++;

    if (i == n_options) {
      log_warn("chop: missing steganographer for %s", options[i-1]);
      goto usage;
    }
      
    if (!steg_is_supported(options[i])) {
      log_warn("chop: steganographer '%s' not supported", options[i]);
      goto usage;
    }
    steg_targets.push_back(steg_new(options[i], this));
  }

  return true;
    
 usage:
  log_warn("chop syntax:\n"
           "\tchop <mode> <up_address> (<down_address> [<steg>])...\n"
           "\t\tmode ~ server|client|socks\n"
           "\t\tup_address, down_address ~ host:port\n"
           "\t\tA steganographer is required for each down_address.\n"
           "\t\tThe down_address list is still required in socks mode.\n"
           "Examples:\n"
           "\tstegotorus chop client 127.0.0.1:5000 "
           "192.168.1.99:11253 http 192.168.1.99:11254 skype\n"
           "\tstegotorus chop server 127.0.0.1:9005 "
           "192.168.1.99:11253 http 192.168.1.99:11254 skype");
  return false;
}




void chop_config_t::socks_force_addr(const char* host, int port) {
  char port_buf[8];
  sprintf(port_buf, "%d", port);

  struct evutil_addrinfo* addr =  resolve_address_port(host, 1, 0, port_buf);
  
  for (vector<struct evutil_addrinfo *>::iterator i = down_addresses.begin();
       i != down_addresses.end(); i++) {
  
    struct sockaddr_in* daddr = (struct sockaddr_in*) ((*i)->ai_addr);
    daddr->sin_addr.s_addr = ((struct sockaddr_in*) addr->ai_addr)->sin_addr.s_addr;
    daddr->sin_port = ((struct sockaddr_in*) addr->ai_addr)->sin_port;
  }

  evutil_freeaddrinfo(addr);

}



struct evutil_addrinfo *
chop_config_t::get_listen_addrs(size_t n) const
{
  if (mode == LSN_SIMPLE_SERVER) {
    if (n < down_addresses.size())
      return down_addresses[n];
  } else if (n == 0) {
    return up_address;
  }

  return 0;
}



struct evutil_addrinfo *
chop_config_t::get_target_addrs(size_t n) const
{
  if (mode == LSN_SIMPLE_SERVER) {
    if (n == 0)
      return up_address;
  } else if (n < down_addresses.size()) {
    return down_addresses[n];
  }
  
  return NULL;
}



const steg_config_t *
chop_config_t::get_steg(size_t n) const
{
  if (n < steg_targets.size())
    return steg_targets[n];
  return NULL;
}


// Circuit methods
circuit_t *
chop_config_t::circuit_create(size_t)
{
  chop_circuit_t *ckt = new chop_circuit_t;
  key_generator *kgen = 0;

  ckt->config = this;

  if (encryption)
    kgen = key_generator::from_passphrase
      ((const uint8_t *)passphrase, sizeof(passphrase) - 1, 0, 0, 0, 0);

  if (mode == LSN_SIMPLE_SERVER) {
    if (encryption) {
      ckt->send_crypt     = gcm_encryptor::create(kgen, 16);
      ckt->send_hdr_crypt = ecb_encryptor::create(kgen, 16);
      ckt->recv_crypt     = gcm_decryptor::create(kgen, 16);
      ckt->recv_hdr_crypt = ecb_decryptor::create(kgen, 16);
    } else {
      ckt->send_crypt     = gcm_encryptor::create_noop();
      ckt->send_hdr_crypt = ecb_encryptor::create_noop();
      ckt->recv_crypt     = gcm_decryptor::create_noop();
      ckt->recv_hdr_crypt = ecb_decryptor::create_noop();
    }
  } else {
    if (encryption) {
      ckt->recv_crypt     = gcm_decryptor::create(kgen, 16);
      ckt->recv_hdr_crypt = ecb_decryptor::create(kgen, 16);
      ckt->send_crypt     = gcm_encryptor::create(kgen, 16);
      ckt->send_hdr_crypt = ecb_encryptor::create(kgen, 16);
    } else {
      ckt->recv_crypt     = gcm_decryptor::create_noop();
      ckt->recv_hdr_crypt = ecb_decryptor::create_noop();
      ckt->send_crypt     = gcm_encryptor::create_noop();
      ckt->send_hdr_crypt = ecb_encryptor::create_noop();
    }

    std::pair<chop_circuit_table::iterator, bool> out;
    do {
      do {
        rng_bytes((uint8_t *)&ckt->circuit_id, sizeof(ckt->circuit_id));
      } while (!ckt->circuit_id);

      out = circuits.insert(make_pair(ckt->circuit_id, (chop_circuit_t *)0));
    } while (!out.second);

    out.first->second = ckt;
  }

  delete kgen;
  return ckt;
}



// Connection methods

conn_t *
chop_config_t::conn_create(size_t index)
{
  chop_conn_t *conn = new chop_conn_t;
  conn->config = this;
  conn->steg = steg_targets.at(index)->steg_create(conn);
  if (!conn->steg) {
    free(conn);
    return 0;
  }

  conn->recv_pending = evbuffer_new();
  return conn;
}




PROTO_DEFINE_MODULE(chop);

