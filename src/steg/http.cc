/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#include "http.h"

#include "shared.h"
#include "schemes.h"
#include "headers.h"

#include "http_server.h"
#include "http_client.h"

#include "jpegSteg.h"
#include "oshacks.h"


/* define to show URI's */
#undef ST_SHOWURI

STEG_DEFINE_MODULE(http);

http_steg_config_t::http_steg_config_t(config_t *cfg)
  : steg_config_t(cfg),
    is_clientside(cfg->mode != LSN_SIMPLE_SERVER),
    pl(),
    shared_secret(NULL),
    hostname(NULL),
    mop(NULL),
    post_reflection(false)

{
  string traces_dir, images_dir, pdfs_dir;

  mop = cfg->mop;
  
  assert(mop != NULL);

  post_reflection = mop->post_reflection();

  //these are owned by the config_t object;
  shared_secret = cfg->shared_secret;
  hostname = cfg->hostname;
    
  traces_dir = cfg->mop->get_steg_datadir(StegData::TRACES);
  images_dir = cfg->mop->get_steg_datadir(StegData::IMAGES);
  pdfs_dir   = cfg->mop->get_steg_datadir(StegData::PDFS);


  zero_payloads(pl);
  
  //log_warn("shared_secret = %s", this->shared_secret);

  if (is_clientside) {
    traces_dir.append("client.out");
    load_payloads(this->pl, traces_dir.c_str());
    /* if we want to do PDF POSTS, then we'll need to load the pdf payloads */
    schemes_clientside_init(this->pl, images_dir.c_str(), pdfs_dir.c_str());
  } else {
    traces_dir.append("server.out");
    load_payloads(this->pl, traces_dir.c_str());
    schemes_serverside_init(this->pl, images_dir.c_str(), pdfs_dir.c_str());
  }

  /* useful when valgrinding to know when things have loaded */
  log_warn("http_steg_config_t() OK");
}

http_steg_config_t::~http_steg_config_t()
{
  free_payloads(this->pl);
}

steg_t *
http_steg_config_t::steg_create(conn_t *conn)
{
  return new http_steg_t(this, conn);
}

http_steg_t::http_steg_t(http_steg_config_t *cf, conn_t *cn)
  : config(cf), conn(cn),
    have_transmitted(false), have_received(false), persist_mode(false),
    transmit_lock(false), accepts_gzip(false), is_gzipped(false), type(HTTP_CONTENT_NONE),  bytes_recvd(0)
{
  //memset(peer_dnsname, 0, sizeof peer_dnsname);
  persist_mode = cf->cfg->persist_mode;
  schemes_init();
}

http_steg_t::~http_steg_t()
{
}

steg_config_t *
http_steg_t::cfg()
{
  return config;
}

void
http_steg_t::successful_reception() 
{
  schemes_success(type);
}

unsigned int
http_steg_t::corrupted_reception() 
{
  schemes_failure(type);
  return bytes_recvd;
}


size_t
http_steg_t::transmit_room(size_t pref, size_t lo, size_t hi)
{
  size_t retval = 0;
  int error = 0;
  log_debug("entering (%p)->transmit_room: type = %d pref = %d, lo = %d, hi = %d", this->conn, type, (int)pref, (int)lo, (int)hi);

  if (have_transmitted || transmit_lock) {
    /* can't send any more on this connection */
    error = 1;
    goto exit_point;
  }

  if (config->is_clientside) {
    error = schemes_clientside_transmit_room(config->pl, pref, lo, hi);
    if(error){
      goto exit_point;
    }
  }
  else {
    if (!have_received) {
      error = 2;
      goto exit_point; 
    }
    error = schemes_serverside_transmit_room(config->pl, type, pref, lo, hi);
    if(error != 0){
      goto exit_point; 
    }
  }
  
  if (hi < lo) {
    /* cannot satisfy this request */
    error = 3;
    goto exit_point;
  }

  
  retval = clamp(pref, lo, hi);

 exit_point:
  if(error){
    log_debug("exiting (%p)->transmit_room: error = %d type = %d pref = %d, lo = %d, hi = %d returning %d", this->conn, error, type, (int)pref, (int)lo, (int)hi, (int)retval);
  }

  return retval; 
}




transmit_t
http_steg_t::transmit(struct evbuffer *source)
{
  transmit_t retval = NOT_TRANSMITTED;

  // need to replace with a real lock... pthreads?
  if (transmit_lock || have_transmitted){
    return retval;
  }
    
  transmit_lock = true;
  
  if (config->is_clientside) {
    retval = http_client_transmit(this, source);
  }
  else {
    retval = http_server_transmit(this, source);
  }

  transmit_lock = false;

  return retval;
}

recv_t
http_steg_t::receive(struct evbuffer *dest)
{
  struct evbuffer *source = conn->inbound();
  recv_t rval = RECV_BAD;
  size_t destbuflen = evbuffer_get_length(dest);
  char *headers = NULL;
  /* get the headers so we can look at things like method, accept-types, content-length and the HTTP status code */
  size_t headers_length;

  if (peek_headers(source, &headers, headers_length) != RECV_GOOD) {    
    log_warn("Peeking at headers failed!");
    return RECV_BAD;
  }
  /* returns 0 if not all the headers have arrived yet; the length if they have; -1 means things failed and don't retry */
  else if(headers_length == 0){
    log_info("Didn't parse headers %" PriSize_t, headers_length);
    return RECV_INCOMPLETE;
  }

  /* !! at this point headers are a null terminated string freshly allocated !! */
    
  if (config->is_clientside) {
    int status = get_http_status_code(headers, headers_length);
    if(status == 200){
      is_gzipped = is_gzip_encoded(headers, headers_length);
      //log_warn("is_gzipped = %d", is_gzipped);
      rval = http_client_receive(this, dest, source, headers, headers_length);
    } else {
      log_warn("Clientside receive got HTTP Code = %d", status);
      rval = RECV_BAD;
    }
  } else {
    accepts_gzip = will_accept_gzip(headers, headers_length);
    //log_warn("accepts_gzip = %d", accepts_gzip);
    rval = http_server_receive(this, dest, source, headers, headers_length);
  }
  
  if (rval != RECV_INCOMPLETE) {
    have_received = true;
    if(persist_mode){
      have_transmitted = false;
      conn_do_flush(conn);
    } else {
      conn->expect_close();
    }
    bytes_recvd = evbuffer_get_length(dest) - destbuflen;
  }

  free(headers);
  //log_warn("http::receive returning %d", rval);
  return rval;
}


