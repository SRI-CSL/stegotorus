/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _STREAM_H
#define _STREAM_H

#include "util.h"
#include "connections.h"
#include "protocol.h"
#include "steg.h"
#include "rng.h"
#include "payloads.h"

#include <event2/buffer.h>


//a secret for those that don't set their secret
#define STEGOTORUS_DEFAULT_SECRET "yadayadablahblah"

class stream_steg_config_t : public steg_config_t
{
public:
  bool is_clientside : 1;
 const char* shared_secret;
 const char* hostname;
 modus_operandi_t* mop;
  
  /* 
   *  As a first attempt we are not going to stream a real feed, but rather a sequence of images
   *  in an image pool
   *  the pool should contain images called: 0.jpg 1.jpg ...  N.jpg  for some N. The pool in the traces
   *  directory N = 99.
   */

  image_pool_p pool;

  
  int capacity;


  STEG_CONFIG_DECLARE_METHODS(stream);
  
  DISALLOW_COPY_AND_ASSIGN(stream_steg_config_t);

};


class stream_steg_t : public steg_t
{
public:
  stream_steg_config_t *config;
  conn_t *conn;
  //char peer_dnsname[512];
  
  size_t stream_id;
  size_t part_count;

  char* boundary;
  size_t boundary_length;

  char* cookie;

  char *headers_in;
  size_t headers_in_length;

  char *headers_out;
  size_t headers_out_length;

  bool headers_sent : 1;
  bool headers_received : 1;

  bool have_transmitted : 1;
  bool have_received : 1;
  bool transmit_lock : 1;

  http_content_t type;

  unsigned int bytes_recvd;

  stream_steg_t(stream_steg_config_t *cf, conn_t *cn);

  STEG_DECLARE_METHODS(stream);

  DISALLOW_COPY_AND_ASSIGN(stream_steg_t);

  transmit_t client_transmit (struct evbuffer *source);

  transmit_t server_transmit (struct evbuffer *source);

  recv_t client_receive(struct evbuffer * dest, struct evbuffer* source);

  recv_t server_receive(struct evbuffer * dest, struct evbuffer* source);

  int transmit_room_aux(bool clientside, size_t pref, size_t& lo, size_t& hi);

  image_p get_cover_image();

};



#endif

