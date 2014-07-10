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
#include "schemes.h"
#include "headers.h"
#include "protocol.h"
#include "crypto.h"
#include "images.h"

#include <ctype.h>
#include <string>
#include <vector>
#include <math.h>

#include <event2/buffer.h>

#include <jel/jel.h>

static bool jpeg_debug = false;

static size_t construct_jpeg_headers(int method, const char* path, const char* host, const char* cookie, unsigned int body_length, char* headers);

static size_t construct_jpeg_body(image_pool_p pool, unsigned char* data,  unsigned int data_length, unsigned char**bodyp);
static size_t deconstruct_jpeg_body(unsigned char *body, unsigned int body_length, unsigned char** datap);


static size_t 
construct_jpeg_body(image_pool_p pool, unsigned char* data,  unsigned int data_length, unsigned char**bodyp){
  if(bodyp != NULL){
    image_p cover = embed_message(pool, data, data_length);
    if(cover != NULL){
      size_t  body_length = (unsigned int)cover->size;
      *bodyp = cover->bytes;
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
deconstruct_jpeg_body(unsigned char *body, unsigned int body_length, unsigned char** datap){
  size_t rval = 0;
  if(datap != NULL){
    unsigned char *message = NULL;
    int message_size = extract_message(&message, body, body_length);
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
  //char *secret = s->config->shared_secret;
  transmit_t retval = NOT_TRANSMITTED;
  conn_t *conn = s->conn;
  char* headers = NULL;
  unsigned char* data = NULL, *body = NULL;
  
  if((source == NULL) || (conn == NULL)){
    log_warn("bad args");
    goto clean_up;
  } else {
    size_t source_length = evbuffer_get_length(source);
    unsigned int body_length = 0, headers_length = 0;
    size_t data_length = 0;
    struct evbuffer *dest = conn->outbound();
    
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

    body_length = construct_jpeg_body(pool, data, data_length, &body);

    if(body_length == 0){
      log_warn("construct_jpeg_body failed to embed data");
      goto clean_up;
    }
    
    headers_length = construct_jpeg_headers(HTTP_GET, NULL, NULL, NULL, body_length, headers);
    
    if(headers_length == 0){
      log_warn("construct_jpeg_headers failed.");
      goto clean_up;
    }

    if(jpeg_debug){
      log_warn("http_server_JPEG_transmit: data_length = %d  body_length = %d", (int)data_length, (int)body_length);
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
  return retval;
  
}


recv_t 
http_client_JPEG_receive(http_steg_t * s, struct evbuffer *dest, char* headers, int headers_length, char* response, int response_length)
{
  char *secret = s->config->shared_secret;
  recv_t retval = RECV_BAD;
  unsigned int data_length = 0, body_length = 0;
  unsigned char *data = NULL, *body = NULL;
  /* use them or .. */
  log_debug("response_length = %d %s %p", (int) response_length, secret, headers);

  body = (unsigned char*)&response[headers_length];
  body_length = response_length - headers_length;
  data_length =  deconstruct_jpeg_body(body, body_length, &data);
  
  if(jpeg_debug){
    log_warn("http_client_JPEG_receive: data_length = %d; body_length %d", (int)data_length,  (int)body_length);
  }

  
  retval = raw2dest(dest,  data_length, data);

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
  char *path = NULL, *headers = NULL;
  char *secret = s->config->shared_secret;
  size_t body_length = 0,  data_length;

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
  body_length = construct_jpeg_body( pool, data, data_length, &body);
  headers_length = construct_jpeg_headers(HTTP_POST, path, HTTP_FAKE_HOST, NULL, body_length, headers);

  if(headers_length == 0){
    log_warn("construct_jpeg_headers failed.");
    goto clean_up;
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
  //the draconian flags we got going here...
  log_debug("http_server_JPEG_post_receive: request_length=%d %s %p", request_length, secret, headers);
  body = (unsigned char*)&request[headers_length];
  body_length = request_length - headers_length;
  data_length =  deconstruct_jpeg_body(body, body_length, &data);
  retval = raw2dest(dest, data_length, data);
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
