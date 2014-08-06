/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "payloads.h"
#include "jpegSteg.h"
#include "base64.h"
#include "b64cookies.h"
#include "connections.h"
#include "shared.h"
#include "headers.h"
#include "schemes.h"
#include "strncasestr.h"
#include "protocol.h"
#include "crypto.h"
#include "oshacks.h"
#include "images.h"


#include <ctype.h>
#include <string>
#include <vector>
#include <math.h>

#include <event2/buffer.h>

#include <jel/jel.h>

static const bool jpeg_debug = false;
static const bool cookie_debug = false;

static jel_knobs_t knobs;
static bool jel_ok = false;

void set_jel_preferences_to_default(){
  //only set these if they haven't already been set
  if(!jel_ok){
    jel_ok = true;
    knobs.embed_length  = true;
    knobs.ecc_blocklen  = 20;     
    knobs.freq_pool     = 16;
    knobs.quality_out   = 75;
    knobs.random_seed   = 0;

  }
}

void set_jel_preferences(jel_knobs_t &knobs_in){
  jel_ok = true;
  knobs.embed_length  = knobs_in.embed_length;
  knobs.ecc_blocklen  = knobs_in.ecc_blocklen;    
  knobs.freq_pool     = knobs_in.freq_pool;
  knobs.quality_out   = knobs_in.quality_out;
  knobs.random_seed   = knobs_in.random_seed;
}

static size_t
construct_jpeg_headers(int method, const char* path, const char* host, const char* cookie, unsigned int body_length, char* headers);

static size_t
construct_jpeg_body(image_pool_p pool, unsigned char* data,  unsigned int data_length, unsigned char**bodyp, int* message_lengthp);

static size_t
deconstruct_jpeg_body(unsigned char *body, unsigned int body_length, unsigned char** datap, int message_length);

static char*
construct_jpeg_cookie(int message_length, char *secret);

static int
deconstruct_jpeg_cookie(char *cookie, char *secret);

static char*
construct_jpeg_cookie_aux(int message_length, char *secret, size_t *clenp);

static int
deconstruct_jpeg_cookie_aux(char *cookie, size_t cookie_length, char *secret);

char*
construct_jpeg_cookie(int message_length, char *secret)
{
  size_t cookie_length = 0;
  char* cookie = construct_jpeg_cookie_aux(message_length, secret, &cookie_length);

  if(cookie_debug){
    if(cookie){
      log_warn(">message_length=%d\nCookie: %s", message_length, cookie);
    } else {
      log_warn("Cookie: NULL");
    }
  }
  
  return cookie;
}

int
deconstruct_jpeg_cookie(char *cookie, char *secret)
{
  size_t cookie_length = strlen(cookie);
  int message_length = deconstruct_jpeg_cookie_aux(cookie, cookie_length, secret);

  if(cookie_debug){

    if(message_length){
      log_warn("<cookie = %s>", cookie);
      log_warn("<cookie_length=%" PriSize_t ">", cookie_length);
      log_warn("<message_length:%d>", message_length);
    } else {
      log_warn("message_length: NIENTE");
    }
    
  }
  return message_length;
}



char*
construct_jpeg_cookie_aux(int message_length, char * secret, size_t *clenp)
{
  char  *cookie = NULL;
  size_t data_length = 0;
  char content[64];
  size_t content_length = 0;
  if( knobs.embed_length ){
    snprintf(content, 64, "0 padding %d", rand());
  } else {
    snprintf(content, 64, "%d padding %d", message_length, rand());
  }
  content_length = strlen(content);
  uchar* data  = defiant_pwd_encrypt(secret, (uchar *)content, content_length, &data_length);
  size_t cookie_length;
  
  if (encode_cookie((char*)data, data_length, &cookie, cookie_length) != RCODE_OK)
    goto clean_up;
  
  *clenp = cookie_length;

 clean_up:
  free(data);
  return cookie;
}

int
deconstruct_jpeg_cookie_aux(char *cookie, size_t cookie_length, char *secret)
{
  uchar* data = (uchar*)xmalloc(2*cookie_length);
  size_t ptext_length = 0;
  size_t data_length;
  char* ptext = NULL;
  int message_length = 0;
  
  if (decode_cookie(cookie, cookie_length, (char*)data, data_length) != RCODE_OK){
    log_warn("decode_cookie of %s FAILED", cookie);
    goto clean_up;
  }
  
  
  ptext = (char *)defiant_pwd_decrypt(secret, data, data_length, &ptext_length);

  if(cookie_debug){
    log_warn("deconstructing cookie %s returned %s", cookie, ptext);
  }

  if(ptext != NULL){
    message_length = atoi(ptext);
  }
  
  if(cookie_debug){
    if(ptext != NULL){
      log_warn("<cookie = %s>", cookie);
      log_warn("<cookie_length=%" PriSize_t ">", cookie_length);
      log_warn("<message_length:%s>", ptext);
    } else {
      log_warn("message_length: NIENTE");
    }
  }
  
 clean_up:
  free(data);
  free(ptext);
  return message_length;
}



static size_t 
construct_jpeg_body(image_pool_p pool, unsigned char* data,  unsigned int data_length, unsigned char**bodyp, int* message_lengthp){
  if((bodyp != NULL) && (message_lengthp != NULL)){
    image_p cover = embed_message(pool, data, data_length,  knobs.embed_length);
    if(cover != NULL){
      size_t  body_length = (unsigned int)cover->size;
      *bodyp = cover->bytes;
      *message_lengthp = knobs.embed_length ? 0 : (int)data_length;
      /* steal ownership of the bytes */
      cover->bytes = NULL;
      free_image(cover);
      return body_length;
    } else {
      log_warn("embed_message failed");
    }
  }
  return 0;
}


static size_t
deconstruct_jpeg_body(unsigned char *body, unsigned int body_length, unsigned char** datap, int message_length){
  size_t rval = 0;
  log_info("deconstruct_jpeg_body: message_length = %d", message_length);
  if(datap != NULL){
    unsigned char *message = NULL;
    int message_size = extract_message(&message, message_length, body, body_length);
    if(message != NULL){
      *datap = message;
      rval = (unsigned int) message_size;
      return rval;
    } else {
      log_warn("extract_message failed");
    }
  }
  return 0;
}



transmit_t 
http_server_JPEG_transmit (http_steg_t * s, struct evbuffer *source){
  image_pool_p pool = s->config->pl.pool;
  char *secret = s->config->shared_secret;
  transmit_t retval = NOT_TRANSMITTED;
  conn_t *conn = s->conn;
  char *headers = NULL, *cookie = NULL;
  unsigned char* data = NULL, *body = NULL;

  if((source == NULL) || (conn == NULL)){
    log_warn("bad args");
    goto clean_up;
  } else {
    size_t source_length = evbuffer_get_length(source);
    unsigned int body_length = 0, headers_length = 0;
    size_t data_length = 0;
    struct evbuffer *dest = conn->outbound();
    int emessage_length = 0;

    headers = (char *)xzalloc(MAX_HEADERS_SIZE);

    if(headers == NULL){
      log_warn("header allocation failed.");
      goto clean_up;
    }

    log_debug("source_length = %d", (int) source_length);

    if (source2raw(source, source_length, &data, data_length) != RCODE_OK) {
      log_warn("extracting raw to send failed");
      goto clean_up;
    }
    
    body_length = construct_jpeg_body(pool, data, data_length, &body, &emessage_length);

    cookie = construct_jpeg_cookie(emessage_length, secret);

    if(body_length == 0){
      log_warn("construct_jpeg_body failed to embed data");
      goto clean_up;
    }
    
    headers_length = construct_jpeg_headers(HTTP_GET, NULL, NULL, cookie, body_length, headers);
    
    if(headers_length == 0){
      log_warn("construct_jpeg_headers failed.");
      goto clean_up;
    }

    if(jpeg_debug){
      log_warn("http_server_JPEG_transmit: data_length = %d  body_length = %d message_length = %d", (int)data_length, (int)body_length, emessage_length);
    }
      
      
    if (evbuffer_add(dest, headers, headers_length)  == -1) {
      log_warn("evbuffer_add() fails for headers");
      goto clean_up;
    }
    
    if (evbuffer_add(dest, body, body_length)  == -1) {
      log_warn("evbuffer_add() fails for body");
      goto clean_up;
    }
    
    evbuffer_drain(source, source_length);
    
    if(SCHEMES_PROFILING){
     profile_data("JPEG", headers_length, body_length, source_length);
    }
    
  }
  
  retval = TRANSMIT_GOOD;
  
 clean_up:
  if(headers != NULL){ free(headers); }
  if(data != NULL){ free(data); }
  if(body != NULL){ free(body); }
  if(cookie != NULL){ free(cookie); }
  return retval;
  
}


recv_t 
http_client_JPEG_receive(http_steg_t * s, struct evbuffer *dest, char* headers, int headers_length, char* response, int response_length)
{
  char *secret = s->config->shared_secret;
  recv_t retval = RECV_BAD;
  unsigned int data_length = 0, body_length = 0;
  unsigned char *data = NULL, *body = NULL;
  char *cookie = NULL;
  size_t cookie_length;
  int message_length = 0;

  /* use them or .. */
  log_debug("response_length = %d %s %p", (int) response_length, secret, headers);

  if (get_cookie(headers, headers_length, &cookie, cookie_length) == RCODE_OK && cookie_length > 0) {
    message_length = deconstruct_jpeg_cookie(cookie, secret);
  } 

  body = (unsigned char*)&response[headers_length];
  body_length = response_length - headers_length;
  data_length =  deconstruct_jpeg_body(body, body_length, &data, message_length);
  
  if(jpeg_debug){
    log_warn("http_client_JPEG_receive: data_length = %d; body_length = %d; message_length = %d", (int)data_length,  (int)body_length, message_length);
  }

  
  retval = raw2dest(dest,  data_length, data);

  if(cookie != NULL){ free(cookie); }
  if(data != NULL){ free(data); }
  return retval;
}

transmit_t 
http_client_JPEG_post_transmit (http_steg_t *s, struct evbuffer *source, conn_t *conn){
  transmit_t retval = NOT_TRANSMITTED;
  image_pool_p pool = s->config->pl.pool;
  struct evbuffer *dest = conn->outbound();
  size_t source_length = evbuffer_get_length(source);
  unsigned int headers_length = 0;
  unsigned char *data = NULL, *body = NULL;
  char *path = NULL, *headers = NULL, *cookie = NULL;
  char *secret = s->config->shared_secret;
  size_t body_length = 0,  data_length;
  int emessage_length = 0;

  if (source2raw(source, source_length, &data, data_length) != RCODE_OK) {
    log_warn("extracting raw to send failed");
    goto clean_up;
  }

  headers = (char *)xzalloc(MAX_HEADERS_SIZE);

  if(headers == NULL){
    log_warn("header allocation failed.");
    goto clean_up;
  }

  log_debug("secret = %s", secret);
  schemes_gen_post_request_path(s->config->pl, &path);  
  body_length = construct_jpeg_body( pool, data, data_length, &body, &emessage_length);

  cookie = construct_jpeg_cookie(emessage_length, secret);
  
  headers_length = construct_jpeg_headers(HTTP_POST, path, HTTP_FAKE_HOST, cookie, body_length, headers);

  if(headers_length == 0){
    log_warn("construct_jpeg_headers failed.");
    goto clean_up;
  }

  if(jpeg_debug){
    log_warn("http_client_JPEG_post_transmit: data_length = %d  body_length = %d message_length = %d", (int)data_length, (int)body_length, emessage_length);
  }

  log_debug("jpeg post headers = <headers>\n%s</headers>", headers);

  if (evbuffer_add(dest, headers, headers_length) == -1) {
    log_warn("evbuffer_add() fails for headers");
    goto clean_up;
  }
  
  if (evbuffer_add(dest, body, body_length) == -1) {
    log_warn("evbuffer_add() fails for data");
    goto clean_up;
  }

  evbuffer_drain(source, source_length);
  if(!s->persist_mode){
    conn->cease_transmission();
  } else {
    conn_do_flush(conn);
  }

  s->type = HTTP_CONTENT_JPEG;
  s->have_transmitted = true;
  s->have_received = false;
  retval = TRANSMIT_GOOD;

  if (SCHEMES_PROFILING){
    profile_data("JPEG", headers_length, body_length, source_length);
  }


 clean_up:
  if(headers != NULL) free(headers);
  if(cookie != NULL) free(cookie);
  if(data != NULL) free(data);
  if(body != NULL) free(body);
  if(path != NULL) free(path); 
  return retval;
}

recv_t 
http_server_JPEG_post_receive(http_steg_t * s, struct evbuffer *dest, char* headers, int headers_length, char* request, int request_length)
{
  recv_t retval = RECV_BAD;
  /* JPEG POST MODE */
  unsigned char *data = NULL, *body = NULL; 
  unsigned int data_length = 0, body_length = 0; 
  char *secret = s->config->shared_secret;
  char *cookie = NULL;
  size_t cookie_length;
  int message_length = 0;
  //the draconian flags we got going here...
  log_debug("http_server_JPEG_post_receive: request_length=%d %s %p", request_length, secret, headers);


  if (get_cookie(headers, headers_length, &cookie, cookie_length) == RCODE_OK && cookie_length > 0) {
    message_length = deconstruct_jpeg_cookie(cookie, secret);
  } 

  body = (unsigned char*)&request[headers_length];
  body_length = request_length - headers_length;
  data_length =  deconstruct_jpeg_body(body, body_length, &data, message_length);


  if(jpeg_debug){
    log_warn("http_server_JPEG_receive: data_length = %d; body_length = %d; message_length = %d", (int)data_length,  (int)body_length, message_length);
  }

  retval = raw2dest(dest, data_length, data);
  if(cookie != NULL)free(cookie);
  if(data != NULL)free(data);
  return retval;
}


size_t
construct_jpeg_headers(int method, const char* path, const char* host, const char* cookie, unsigned int body_length, char* headers)
{
  size_t headers_length = MAX_HEADERS_SIZE;

  if(method == HTTP_GET){
    if (gen_response_header(JPEG_CONTENT_TYPE, cookie, 0, body_length, headers, headers_length, headers_length) != RCODE_OK)
      goto err;
  } else if(method == HTTP_POST){
    if (gen_post_header(JPEG_CONTENT_TYPE, path, host, cookie, 0, body_length, headers, headers_length, headers_length) != RCODE_OK)
      goto err;
  } else {
    log_warn("Bad method %d to construct_jpeg_headers (HTTP_GET = %d, HTTP_POST = %d)", method, HTTP_GET, HTTP_POST);
  }
  
  return headers_length;

 err:
  return 0;
}
