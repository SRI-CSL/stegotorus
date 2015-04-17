/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */
#include <string>

#include "stream.h"

#include "shared.h"
#include "schemes.h"
#include "headers.h"
#include "mhexSteg.h"
#include "mrawSteg.h"
#include "mjpegSteg.h"
#include "strncasestr.h"
#include "modus_operandi.h"
#include "oshacks.h"

static size_t obj_counter = 0;

typedef enum stream_type {
  MHEX,
  MRAW,
  MJPEG,
} stream_type_t;

//switch the actual module being used by setting stype:
//static const stream_type_t stype = MHEX;
//static const stream_type_t stype = MRAW;
static const stream_type_t stype = MJPEG;

static char *generateBoundary();
static char *parseBoundary(char *headers, size_t headers_length);

STEG_DEFINE_MODULE(stream);

int stream_transmit_room(bool clientside, size_t pref, size_t& lo, size_t& hi);


stream_steg_config_t::stream_steg_config_t(config_t *cfg)
  : steg_config_t(cfg),
    is_clientside(cfg->mode != LSN_SIMPLE_SERVER),
    shared_secret(NULL),
    hostname(NULL),
    mop(NULL),
    pool(NULL),
    capacity(0)

{
  std::string stream_dir;

  mop = cfg->mop;
  
  assert(mop != NULL);

  stream_dir = cfg->mop->get_steg_datadir(StegData::STREAM);

  //these are owned by the config_t object;
  shared_secret = cfg->shared_secret;
  hostname = cfg->hostname;

  if(0){
    log_warn("modus_operandi = %p", cfg->mop);
    log_warn("shared_secret = %s", shared_secret); 
    log_warn("hostname = %s", hostname); 
    log_warn("stream_dir = %s", stream_dir.c_str()); 
  }


  if(!is_clientside){
    this->pool = load_images(stream_dir.c_str(), 100);

    //n.b.  pushing capacity to its limits just causes corruption.
    this->capacity = this->pool->the_images_min_payload / 2;
    
  }

  /* useful when valgrinding to know when things have loaded */
  log_warn("stream_steg_config_t() OK");
}

stream_steg_config_t::~stream_steg_config_t()
{
  free_image_pool(this->pool);
}

steg_t *
stream_steg_config_t::steg_create(conn_t *conn)
{
  return new stream_steg_t(this, conn);
}

stream_steg_t::stream_steg_t(stream_steg_config_t *cf, conn_t *cn)
  : config(cf), conn(cn),
    stream_id(0), part_count(0),
    boundary(NULL), boundary_length(0),
    cookie(NULL),
    headers_in(NULL),  headers_in_length(0), 
    headers_out(NULL), headers_out_length(0),
    headers_sent(false), headers_received(false),
    have_transmitted(false), have_received(false),
    transmit_lock(false), type(HTTP_CONTENT_NONE),  bytes_recvd(0)
{
  //memset(peer_dnsname, 0, sizeof peer_dnsname);
  schemes_init();
  //server generates one; the client gets it in the headers (in the content-type)
  if(!config->is_clientside){
    boundary = generateBoundary();
    boundary_length  = strlen(boundary);
  } 

  stream_id = obj_counter++;
  /*
    log_warn("new stream_steg_t(%" PriSize_t ")", stream_id);
    print_trace ();
  */
}

stream_steg_t::~stream_steg_t()
{
  free(boundary);
  free(headers_in);
  free(headers_out);
}

steg_config_t *
stream_steg_t::cfg()
{
  return config;
}

image_p
stream_steg_t::get_cover_image(){
  stream_steg_config_t *c = this->config;
  if(c->pool != NULL){
    int modulus = c->pool->the_images_offset;
    int index = part_count % modulus;
    return get_image_by_index(c->pool, index);
  }
  return NULL;
}

void
stream_steg_t::successful_reception() 
{
  schemes_success(type);
}

unsigned int
stream_steg_t::corrupted_reception() 
{
  schemes_failure(type);
  return bytes_recvd;
}


size_t
stream_steg_t::transmit_room(size_t pref, size_t lo, size_t hi)
{
  size_t retval = 0;
  int error = 0;
  log_debug("entering (%p)->transmit_room: type = %d pref = %d, lo = %d, hi = %d", this->conn, type, (int)pref, (int)lo, (int)hi);

  if (transmit_lock) {
    /* can't send any more on this connection */
    error = 1;
    goto exit_point;
  }

  if (config->is_clientside) {
    if (have_transmitted) {
      /* can't send any more on this connection */
      error = 1;
      goto exit_point;
    }
    error = transmit_room_aux(true, pref, lo, hi);
    if(error){
      goto exit_point;
    }
  }
  else {
    if (!have_received) {
      error = 2;
      goto exit_point; 
    }

    if (rand() % 5 != 0) {
      error = 3;
      goto exit_point;
    }

    error = transmit_room_aux(false, pref, lo, hi);
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
stream_steg_t::transmit(struct evbuffer *source)
{
  transmit_t retval = NOT_TRANSMITTED;

  // need to replace with a real lock... pthreads?
  if ( transmit_lock ){
    log_warn("stream_steg_t::transmit: retval = %d\n", retval);
    return retval;
  }
    
  transmit_lock = true;

  if (config->is_clientside) {
    retval = client_transmit(source);
  }
  else {
    retval = server_transmit(source);
  }

  transmit_lock = false;

  return retval;
}

recv_t
stream_steg_t::receive(struct evbuffer *dest)
{
  struct evbuffer *source = conn->inbound();
  recv_t rval = RECV_BAD;
  size_t destbuflen = evbuffer_get_length(dest);

  /* if this is the first receive, then we need to get the headers */
  if(!headers_received){
    if (peek_headers(source, &headers_in, headers_in_length) != RECV_GOOD) {
      log_warn("Peeking at http headers failed!");
      return RECV_BAD;
    }
    /* returns 0 if not all the headers have arrived yet; the length if they have; -1 means things failed and don't retry */
    else if(headers_in_length == 0){
      log_info("Didn't parse headers %" PriSize_t, headers_in_length);
      return RECV_INCOMPLETE;
    }


    if (config->is_clientside) {
      int status = get_http_status_code(headers_in, headers_in_length);
      if(status != 200){
        log_warn("Clientside receive got HTTP Code = %d", status);
        return RECV_BAD;
      }
      this->boundary = parseBoundary(headers_in, headers_in_length);
      if(this->boundary == NULL){
        log_warn("Clientside receive got no boundary");
        return RECV_BAD;
      }
    }

    
    
    evbuffer_drain(source, headers_in_length);
    headers_received = true;
  }
  
  /* !! at this point headers are a null terminated string freshly allocated !! */
    
  if (config->is_clientside) {
    rval = client_receive(dest, source);
  } else {
    rval = server_receive(dest, source);
  }
  

  if (rval != RECV_INCOMPLETE) {
    //must be either RECV_GOOD or RECV_BAD
    have_received = true;
    conn_do_flush(conn);
    bytes_recvd = evbuffer_get_length(dest) - destbuflen;
  }
  
  //log_warn("stream::receive returning %d", rval);
  return rval;
}


transmit_t
stream_steg_t::client_transmit (struct evbuffer *source)
{
  transmit_t retval = NOT_TRANSMITTED;
  log_info("%p", source);
  struct evbuffer *dest = conn->outbound();

  switch(stype){
  case MJPEG: retval = stream_client_MJPEG_transmit(this, dest, source); break;
  case MRAW: retval = stream_client_MRAW_transmit(this, dest, source); break;
  case MHEX: retval = stream_client_MHEX_transmit(this, dest, source); break;
  default: return retval;
  }
  
  return retval;
}

transmit_t
stream_steg_t::server_transmit (struct evbuffer *source)
{
  transmit_t retval = NOT_TRANSMITTED;
  log_info("%p", source);
  struct evbuffer *dest = conn->outbound();

  switch(stype){
  case MJPEG: retval = stream_server_MJPEG_transmit(this, dest, source); break;
  case MRAW: retval = stream_server_MRAW_transmit(this, dest, source); break;
  case MHEX: retval = stream_server_MHEX_transmit(this, dest, source); break;
  default: return retval;
  }

  if (retval == TRANSMIT_GOOD) {
    have_transmitted = true;
    conn_do_flush(conn);
  }

  return retval;
}

int
stream_steg_t::transmit_room_aux(bool clientside, size_t pref, size_t& lo, size_t& hi)
{
  log_info("clientside= %d pref=%" PriSize_t "lo=%" PriSize_t " hi=%" PriSize_t, clientside, pref, lo, hi);
  if(clientside){
    /* uri transmit */
    if (lo < (MIN_COOKIE_SIZE*3)/4)
      lo = (MIN_COOKIE_SIZE*3)/4;
    if (hi > (MAX_COOKIE_SIZE*3)/4)
      hi = (MAX_COOKIE_SIZE*3)/4;
  } else {
    /* mjpeg transmit */
    hi = this->config->capacity;
  }
  return 0;
}

recv_t
stream_steg_t::client_receive(struct evbuffer * dest, struct evbuffer* source)
{
  recv_t retval = RECV_BAD;
  log_info("%p %p", dest, source);
  switch(stype){
  case MJPEG: retval = stream_client_MJPEG_receive(this, dest, source); break;
  case MRAW: retval = stream_client_MRAW_receive(this, dest, source); break;
  case MHEX: retval = stream_client_MHEX_receive(this, dest, source); break;
  default: return retval;
  }
  return retval;
}

recv_t
stream_steg_t::server_receive(struct evbuffer * dest, struct evbuffer* source)
{
  recv_t retval = RECV_BAD;
  log_info("%p %p", dest, source);
  switch(stype){
  case MJPEG: retval = stream_server_MJPEG_receive(this, dest, source); break;
  case MRAW: retval = stream_server_MRAW_receive(this, dest, source); break;
  case MHEX: retval = stream_server_MHEX_receive(this, dest, source); break;
  default: return retval;
  }
  return retval;
}



//<boundary stuff>
/*
  The boundary's length must be between 1 and 70  and if it contains
  odd characters then it must be in quotes:

  Content-Type: multipart/mixed; boundary=gc0pJq0M:08jU534c0p

  is invalid  (because of the colon) and must instead be represented as

  Content-Type: multipart/mixed; boundary="gc0pJq0M:08jU534c0p"

  They also must not appear in the body of each part...
*/
  
static bool boundaryOK = false;
static const int yahexcharlen = 62;
static const char yahexchar[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static size_t common_boundaries_length = 0;
static const char* common_boundaries[] =  {
  "myboundary",
  "endofsection",
  "imageheader",
  "BoundaryString",
  "spionisto",
  "aaboundary",
  "ipcamera",
  NULL
};

char *generateBoundary(){

  if(boundaryOK){
    size_t i = 0;
    while(common_boundaries[i] != NULL){
      i++;
    }
    common_boundaries_length = i;
    srand(time(NULL));
    boundaryOK = true;
  }
  
  if((common_boundaries_length > 0) && (rand() % 2) == 0){
    return strdup(common_boundaries[rand() % 4]);
  } else {
    // the length will be between 10 and 70
    int buffz = 11 + (rand() % 60);
    char *buff = (char *)xzalloc(buffz + 1);
    
    
    for(int i = 0; i < buffz; i++){
      buff[i] =  yahexchar[rand() % yahexcharlen];
    }
    buff[buffz] = '\0';
    
    return buff;
  }
}

char *parseBoundary(char *headers, size_t headers_length){
  char* boundary = NULL;
  char *content_type = NULL;
  size_t content_type_length = 0;
  rcode_t rcode = get_content_type(headers, headers_length, &content_type, content_type_length);
  if(rcode == RCODE_OK){
    char key[] = "boundary=";
    size_t key_length = strlen(key);
    char *boundary_start = strncasestr(content_type, key, content_type_length);
    if(boundary_start != NULL){
      boundary = strdup(&boundary_start[key_length]);
    }
  }
  free(content_type);
  return boundary;
}
//</boundary stuff>
