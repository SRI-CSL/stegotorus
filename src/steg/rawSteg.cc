/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "payloads.h"
#include "rawSteg.h"
#include "headers.h"
#include "shared.h"
#include "schemes.h"
#include "oshacks.h"


static size_t construct_raw_headers(int method, const char* path, const char* host, const char* cookie, size_t body_length, char* headers);

transmit_t
http_server_RAW_transmit (http_steg_t * s, struct evbuffer *source){
  const char *secret = s->config->shared_secret;
  transmit_t retval = NOT_TRANSMITTED;
  conn_t *conn = s->conn;
  char* headers = NULL;
  unsigned char* data = NULL;
  size_t source_length = evbuffer_get_length(source);
  size_t data_length = 0, headers_length = 0;
  int addcode = 0;
  struct evbuffer *dest = conn->outbound();

  if((source == NULL) || (conn == NULL)){
    log_warn("bad args");
    goto clean_up;
  } 
  
  headers = (char *)xzalloc(MAX_HEADERS_SIZE);

  if(headers == NULL){
    log_warn("header allocation failed.");
    goto clean_up;
  }
  
  log_debug("source_length = %d secret=%s", (int) source_length, secret);
  
  if (source2raw(source, source_length, &data, data_length) != RCODE_OK)
    goto clean_up;

  headers_length = construct_raw_headers(HTTP_GET, NULL, NULL, NULL, data_length, headers);
  
  if(headers_length == 0){
    log_warn("construct_raw_headers failed.");
      goto clean_up;
  }
  addcode = evbuffer_add(dest, headers, headers_length);
  
  if (addcode == -1) {
    log_warn("evbuffer_add() fails for headers");
    goto clean_up;
  }
  addcode = evbuffer_add(dest, data, data_length);
  
  if (addcode == -1) {
    log_warn("evbuffer_add() fails for body");
    goto clean_up;
  }
  
  evbuffer_drain(source, source_length);

  if(SCHEMES_PROFILING){
    profile_data("RAW", headers_length, data_length, source_length);
  }

  //log_warn("RAW:\t%d\t", (int)source_length);
  retval = TRANSMIT_GOOD;

 clean_up:
  if(headers != NULL){ free(headers); }
  if(data != NULL){ free(data); }
  return retval;
}

recv_t
http_client_RAW_receive (http_steg_t * s, struct evbuffer *dest, char* headers, size_t headers_length, char* response, size_t response_length)
{
  const char *secret = s->config->shared_secret;
  recv_t retval = RECV_BAD;
  size_t data_length = 0;
  char *data = NULL;

  /* here to stop whining about unused variables sheesh! */
  log_debug("response_length = %" PriSize_t " secret=%s headers = %p", response_length, secret, headers);
  data = &response[headers_length];
  data_length = response_length - headers_length;
  
  retval = raw2dest(dest,  data_length, (uchar*)data);  
  return retval;
}

transmit_t
http_client_RAW_post_transmit (http_steg_t *s, struct evbuffer *source, conn_t *conn)
{
  transmit_t retval = NOT_TRANSMITTED;
  struct evbuffer *dest = conn->outbound();
  size_t source_length = evbuffer_get_length(source);
  size_t headers_length = 0;
  char *path = NULL, *headers = NULL;
  unsigned char *data = NULL;
  size_t data_length = 0;
  int addcode;
  const char *secret = s->config->shared_secret;

  log_debug("secret = %s", secret);

  if  (source2raw(source, source_length, &data, data_length) != RCODE_OK) {
    log_warn("extracting bytes to send failed");
    goto clean_up;
  }
  
  headers = (char *)xzalloc(MAX_HEADERS_SIZE);

  if(headers == NULL){
    log_warn("header allocation failed.");
    goto clean_up;
  }

  schemes_gen_post_request_path(s->config->pl, &path);
  headers_length = construct_raw_headers(HTTP_POST, path, HTTP_FAKE_HOST, NULL, data_length, headers);

  if(headers_length == 0){
    log_warn("construct_raw_headers failed.");
    goto clean_up;
  }
  //log_warn("post headers = <headers>\n%s</headers>", headers);
  addcode = evbuffer_add(dest, headers, headers_length);

  if (addcode == -1) {
    log_warn("evbuffer_add() fails for headers");
    goto clean_up;
  }
  addcode = evbuffer_add(dest, data, data_length);

  if (addcode == -1) {
    log_warn("evbuffer_add() fails for data");
    goto clean_up;
  }
  evbuffer_drain(source, source_length);

  if(!s->persist_mode){
    conn->cease_transmission();
  } else {
    conn_do_flush(conn);
  }

  s->type = HTTP_CONTENT_RAW;
  s->have_transmitted = true;
  s->have_received = false;
  retval = TRANSMIT_GOOD;

  if(SCHEMES_PROFILING){
    profile_data("RAW", headers_length, data_length, source_length);
  }

 clean_up:
  if(headers != NULL)free(headers);
  if(data != NULL)free(data);
  if(path != NULL){ free(path); }
  return retval;
}



recv_t 
http_server_RAW_post_receive(http_steg_t * s, struct evbuffer *dest, char* headers, size_t headers_length, char* request, size_t request_length)
{
  recv_t retval = RECV_BAD;
  /* RAW POST MODE */
  size_t data_length = 0;
  uchar* data;
  const char *secret = s->config->shared_secret;

  log_debug("http_server_RAW_post_receive: request_length =  %" PriSize_t " secret = %s", request_length, secret);
  //sigh: to keep the compiler happy with the draconian flags we got going here...
  log_info("<headers>%s</headers>", headers);
  data = (uchar*)&request[headers_length];
  data_length = request_length - headers_length;
  
  retval = raw2dest(dest,  data_length, data);
  return retval;
}



size_t
construct_raw_headers(int method, const char* path, const char* host, const char* cookie, size_t body_length, char* headers){

  size_t headers_length = MAX_HEADERS_SIZE;

  if(method == HTTP_GET){
    if (gen_response_header(RAW_CONTENT_TYPE, cookie, 0, body_length, headers, headers_length, headers_length) != RCODE_OK)
      goto err;

  } else if(method == HTTP_POST){
    if (gen_post_header(RAW_CONTENT_TYPE, path, host, cookie, 0, body_length, headers, headers_length, headers_length) != RCODE_OK)
      goto err;
  } else {
    log_warn("Bad method %d to construct_raw_headers(HTTP_GET = %d, HTTP_POST = %d)", method, HTTP_GET, HTTP_POST);
  }
  
  return headers_length;

 err:
  return 0;
}
