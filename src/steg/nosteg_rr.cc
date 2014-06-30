/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "connections.h"
#include "protocol.h"
#include "steg.h"
#include "rng.h"
#include "strncasestr.h"
#include <event2/buffer.h>


class nosteg_rr_steg_config_t : public steg_config_t
{
public:
  STEG_CONFIG_DECLARE_METHODS(nosteg_rr);
};

class nosteg_rr_steg_t : public steg_t
{
public:
  nosteg_rr_steg_config_t *config;
  conn_t *conn;
  
  bool can_transmit : 1;
  bool did_transmit : 1;
  int seen_so_far;
  
  nosteg_rr_steg_t(nosteg_rr_steg_config_t *cf, conn_t *cn);

  STEG_DECLARE_METHODS(nosteg_rr);

  DISALLOW_COPY_AND_ASSIGN(nosteg_rr_steg_t);

};


STEG_DEFINE_MODULE(nosteg_rr);

nosteg_rr_steg_config_t::nosteg_rr_steg_config_t(config_t *cfg)
  : steg_config_t(cfg)
{

}

nosteg_rr_steg_config_t::~nosteg_rr_steg_config_t()
{
}

steg_t *
nosteg_rr_steg_config_t::steg_create(conn_t *conn)
{
  return new nosteg_rr_steg_t(this, conn);
}

nosteg_rr_steg_t::nosteg_rr_steg_t(nosteg_rr_steg_config_t *cf,
                                   conn_t *cn)
  : config(cf), conn(cn),
    can_transmit(cf->cfg->mode != LSN_SIMPLE_SERVER),
    did_transmit(false),
    seen_so_far (0)

{
}

nosteg_rr_steg_t::~nosteg_rr_steg_t()
{
}

steg_config_t *
nosteg_rr_steg_t::cfg()
{
  return config;
}



void
nosteg_rr_steg_t::successful_reception() {};

unsigned int
nosteg_rr_steg_t::corrupted_reception() {return 0;};




size_t
nosteg_rr_steg_t::transmit_room(size_t pref, size_t, size_t)
{

  return can_transmit ? pref : 0;

}




transmit_t
nosteg_rr_steg_t::transmit(struct evbuffer *source)
{
  log_assert(can_transmit);
  char buf[4];
  rcode_t rcode;
  
  struct evbuffer *dest = conn->outbound();
  int len = evbuffer_get_length(source);
  
  rcode = memncpy(buf, 4, &len, 4);

  assert(rcode == RCODE_OK);

  log_debug(conn, "transmitting %lu bytes",
            (unsigned long)evbuffer_get_length(source));


  if (evbuffer_add(dest, buf, sizeof(buf))) {
    log_warn(conn, "failed to transfer buffer");
    return NOT_TRANSMITTED;
  }



  if (evbuffer_add_buffer(dest, source)) {
    log_warn(conn, "failed to transfer buffer");
    return NOT_TRANSMITTED;
  }


  did_transmit = true;
  can_transmit = false;
  conn->cease_transmission();

  return TRANSMIT_GOOD;
}



recv_t
nosteg_rr_steg_t::receive(struct evbuffer *dest)
{
  struct evbuffer *source = conn->inbound();
  int datalen;

  log_debug(conn, "%s-side receiving %lu bytes",
            config->cfg->mode == LSN_SIMPLE_SERVER ? "server" : "client",
            (unsigned long)evbuffer_get_length(source));

  int len = evbuffer_get_length(source);

  if (len < 4)
    return RECV_INCOMPLETE;

  evbuffer_copyout(source, &datalen, 4);

  if (len < datalen)
    return RECV_INCOMPLETE;
    
  if (evbuffer_drain(source, 4)) {
    log_warn(conn, "failed to drain buffer");
    return RECV_BAD;
  }



  if (evbuffer_add_buffer(dest, source)) {
    log_warn(conn, "failed to transfer buffer");
    return RECV_BAD;
  }
  


  if (config->cfg->mode != LSN_SIMPLE_SERVER) {
    conn->expect_close();
  } else if (!did_transmit) {
    can_transmit = true;
    conn->expect_close();
    conn->transmit_soon(100);
  }

  return RECV_GOOD;
}

