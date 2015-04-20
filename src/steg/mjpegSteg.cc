/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "payloads.h"
#include "mjpegSteg.h"
#include "headers.h"
#include "shared.h"
#include "schemes.h"
#include "strncasestr.h"
#include "oshacks.h"
#include "modus_operandi.h"


static const bool debug_headers = false;
static const bool traffic_write = false;

static
rcode_t
stream_gen_uri(char* uri, size_t uri_sz, char* data, size_t& datalen);

static
size_t
construct_mjpeg_headers(stream_steg_t *s);

static 
size_t
construct_mjpeg_part_headers(stream_steg_t *s, size_t body_length, char* pheaders);

static
size_t
construct_mjpeg_part_body(jel_knobs_t* knobs, image_p image, unsigned char* data,  unsigned int data_length, unsigned char**bodyp);

static
size_t
deconstruct_mjpeg_part_body(jel_knobs_t* knobs, unsigned char *body, unsigned int body_length, unsigned char** datap);



static size_t 
construct_mjpeg_part_body(jel_knobs_t* knobs, image_p image, unsigned char* data,  unsigned int data_length, unsigned char**bodyp){
  if(bodyp != NULL){
    //note we have to embed the length since we have no side channel
    image_p cover = embed_message_in_image(knobs, image, data, data_length);
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
deconstruct_mjpeg_part_body(jel_knobs_t* knobs, unsigned char *body, unsigned int body_length, unsigned char** datap){
  size_t rval = 0;
  if(datap != NULL){
    unsigned char *message = NULL;
    int message_size = 0;
    //note we have are embedding the length since we have no side channel
    message_size = extract_message(knobs, &message, message_size, body, body_length);
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
stream_server_MJPEG_transmit (stream_steg_t *s, struct evbuffer *dest, struct evbuffer *source){
  const char *secret = s->config->shared_secret;
  jel_knobs_t* knobs = s->config->mop->jel_knobs();
  transmit_t retval = NOT_TRANSMITTED;
  
  unsigned char* data = NULL, *body = NULL;
  size_t source_length = evbuffer_get_length(source);
  size_t data_length = 0, body_length;
  int addcode = 0;
  char *pheaders =  NULL;
  size_t pheaders_length = 0;

  image_p cover;
  
  int packet_id = 0;

  FILE* log = NULL;


  if((source == NULL) || (dest == NULL)){
    log_warn("bad args");
    goto clean_up;
  }

  if(s->boundary == NULL){
    log_warn("no boundary");
    goto clean_up;
  }

  
  if((s->headers_out == NULL) && !s->headers_sent){

    /* must be the beginning of the stream; need to make and send the headers */
    s->headers_out = (char *)xzalloc(MAX_HEADERS_SIZE);
    
    if(s->headers_out == NULL){
      log_warn("header allocation failed.");
      goto clean_up;
    }
    
    s->headers_out_length = construct_mjpeg_headers(s);

    if(s->headers_out_length == 0){
      log_warn("construct_mjpeg_headers failed.");
      goto clean_up;
    }
    
    addcode = evbuffer_add(dest, s->headers_out, s->headers_out_length);
  
    if (addcode == -1) {
      log_warn("evbuffer_add() fails for headers_out");
      goto clean_up;
    }

    s->headers_sent = true;
    
  }

  
  log_debug("source_length = %d secret=%s", (int) source_length, secret);
  
  if (source2raw(source, source_length, &data, data_length) != RCODE_OK){
    log_warn("source2raw fails");
    goto clean_up;
  }

  cover = s->get_cover_image();

  if(cover == NULL){
    log_warn("s->get_cover_image() fails");
    goto clean_up;
  }

  body_length = construct_mjpeg_part_body(knobs, cover, data, data_length, &body);
  
  if(body_length == 0){
    log_warn("construct_mjpeg_part_body failed to embed data");
    goto clean_up;
  }


  pheaders =  (char *)xzalloc(MJPEG_MAX_PART_HEADERS_SIZE);
  pheaders_length = construct_mjpeg_part_headers(s, body_length, pheaders);

  if(debug_headers){
    packet_id = atol(&pheaders[s->boundary_length + 1]);
  }

  addcode = evbuffer_add(dest, pheaders, pheaders_length);
  
  if (addcode == -1) {
    log_warn("evbuffer_add() fails for body");
    goto clean_up;
  }

  addcode = evbuffer_add(dest, body, body_length);

  if (addcode == -1) {
    log_warn("evbuffer_add() fails for body");
    goto clean_up;
  }
  
  if(traffic_write){

    log_warn("packet_id = %d stream_id = %" PriSize_t " part_count = %"  PriSize_t "", packet_id, s->stream_id,  s->part_count);

    log = fopen("./server.log", "a");

    fprintf(log, "%s[...] data_length: %" PriSize_t  "\n", pheaders, data_length);
    
    fclose(log);


  }
  
  evbuffer_drain(source, source_length);

  s->part_count++;
  
  retval = TRANSMIT_GOOD;

 clean_up:
  if(body != NULL){ free(body); }
  if(data != NULL){ free(data); }
  if(pheaders != NULL){ free(pheaders); }

  return retval;
}

recv_t
stream_client_MJPEG_receive (stream_steg_t * s, struct evbuffer *dest, struct evbuffer *source)
{
  recv_t retval = RECV_BAD;
  jel_knobs_t* knobs = s->config->mop->jel_knobs();

  /* here to stop whining about unused variables sheesh! */
  log_debug("%p %p %p", s, dest, source);

  /*
    At this stage we have received the main headers, so we need to see if we have a "complete" part.
    So we:
    1. see if we can get the pheaders
    2. see if they make sense (start with  --"s->boundary")
    3. get the content length field
    4. see if we have enough data.
  */
  char *pheaders = NULL;
  /* get the headers so we can look at things like method, accept-types, content-length and the HTTP status code */
  size_t pheaders_length;

  char *response = NULL; 
  size_t response_length; 
  
  unsigned char *data = NULL; 
  size_t data_length; 
  
  unsigned char *body = NULL; 
  size_t body_length; 
  
  int packet_id = 0;

  FILE* log = NULL;

  if (peek_headers(source, &pheaders, pheaders_length) != RECV_GOOD) {    
    log_warn("Peeking at headers failed!");
    retval = RECV_BAD;
    goto exit;
  }
  else if(pheaders_length == 0){
    log_info("Didn't parse pheaders %" PriSize_t, pheaders_length);
    retval = RECV_INCOMPLETE;
    goto exit;
  }

  /* !! at this point headers are a null terminated string freshly allocated !! */
  if(strncmp("--", pheaders, 2) ||
     strncmp(s->boundary, &pheaders[2], s->boundary_length)){
    log_warn("pheaders did not begin with the boundary: %s!", pheaders);
    retval = RECV_BAD;
    goto exit;
  }

  if(debug_headers){
    packet_id = atol(&pheaders[s->boundary_length + 1]);
  }
  
  /* could use this later 
     http_content_t find_content_type(char* headers, size_t headers_length);
  */
  
  if (peek_content(source, pheaders_length, pheaders, &response, response_length) != RCODE_OK) {
    log_info("Failed to get all of the response");
    return RECV_INCOMPLETE;
  }
  
  body = (unsigned char*)&response[pheaders_length];
  body_length = response_length - pheaders_length;

  data_length = deconstruct_mjpeg_part_body(knobs, body, body_length, &data);

  if(traffic_write){

    log_warn("packet_id = %d stream_id = %" PriSize_t " part_count = %"  PriSize_t "", packet_id, s->stream_id,  s->part_count);

    log = fopen("./client.log", "a");

    fprintf(log, "%s[...] data_length: %" PriSize_t  "\n", pheaders, data_length);
    
    fclose(log);

  }
  
  retval = raw2dest(dest,  data_length, data);
  
  if (evbuffer_drain(source, response_length) == -1) {
    log_warn("failed to drain source");
  } 
  
  if (response != NULL){ free(response); }

  s->part_count++;
  
 exit:
  
  free(pheaders);
  
  return retval;
}

static size_t packet_id = 0;

size_t
construct_mjpeg_part_headers(stream_steg_t * s, size_t body_length, char* pheaders){
  log_debug("%p %" PriSize_t " %p",  s, body_length, pheaders);
  if(debug_headers){
    snprintf(pheaders, MJPEG_MAX_PART_HEADERS_SIZE, "--%s %" PriSize_t  " %" PriSize_t  "\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\n\r\n", s->boundary, packet_id++, s->stream_id, (int)body_length);
  } else {
    snprintf(pheaders, MJPEG_MAX_PART_HEADERS_SIZE, "--%s\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\n\r\n", s->boundary, (int)body_length);
  }
  return strlen(pheaders);
}


#define HEADERS_FORMAT  "HTTP/1.0 200 OK\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nExpires: Thu, 01 Dec 1994 16:00:00 GMT\r\nConnection: close\r\nContent-Type: multipart/x-mixed-replace; boundary=%s\r\n\r\n"

size_t
construct_mjpeg_headers(stream_steg_t *s){
  size_t headers_length = strlen(HEADERS_FORMAT) + 71;

  log_debug("%p", s);

  s->headers_out =  (char*)xzalloc(headers_length + 1);

  snprintf(s->headers_out, headers_length, HEADERS_FORMAT, s->boundary);
  
  //memcpy(s->headers_out, headers, headers_length);
  
  s->headers_out[headers_length] = '\0';
  
  s->headers_out_length = strlen(s->headers_out);
  
  return  s->headers_out_length;
}



recv_t
mjpeg2dest(struct evbuffer *dest, size_t data_length, uchar *data)
{
  int addcode;
  recv_t retval = RECV_BAD;
  struct evbuffer *scratch = NULL;

  if(data_length == 0){
    log_warn("zero characters received\n");
    goto clean_up;
  }
  
  /* get a scratch buffer */
  scratch = evbuffer_new();
  if (!scratch){
    goto clean_up;
  }
  
  /* make room for the mjpeg data */
  if (evbuffer_expand(scratch, data_length)) {
    log_warn("evbuffer expand failed \n");
    goto clean_up;
  }
  
  addcode = evbuffer_add(scratch, data, data_length);
  if (addcode == -1) {
    log_warn("evbuffer_add failed");
    goto clean_up;
  }
  

  /* add the scratch buffer to dest */
  addcode = evbuffer_add_buffer(dest, scratch);
  if (addcode == -1) {
    log_warn("evbuffer_add_buffer failed");
    goto clean_up;
  }

  retval = RECV_GOOD;

 clean_up:

  if(scratch != NULL){ evbuffer_free(scratch); }

  return retval;

}

/* minor simplification of http_client_uri_transmit in http_client.cc */
transmit_t
stream_client_MJPEG_transmit (stream_steg_t * s, struct evbuffer *dest, struct evbuffer *source){
  transmit_t retval = NOT_TRANSMITTED;
  size_t source_length = evbuffer_get_length(source);
  char *data = NULL, *outbuf = NULL;
  size_t datalen = 0;
  size_t outbufsz = 3*1024;
  const char accept[] = "\r\nAccept: */*";
  const char *hostname = s->config->hostname;

  if (source2hex(source, source_length, &data, datalen) != RCODE_OK) {
    log_warn("source2hex called returned negative value");
    goto clean_up;
  }

  outbuf = (char *)xzalloc(outbufsz);

  if (outbuf == NULL) {
    log_warn("outbuf allocation failed.");
    goto clean_up;
  }

  /*
  if (s->peer_dnsname[0] == '\0')
    lookup_peer_name_from_ip(s->conn->peername, s->peer_dnsname, sizeof(s->peer_dnsname));
  */
  
  // loop till success
  while (stream_gen_uri(outbuf, outbufsz, data, datalen) != RCODE_OK){ };
  
  if (evbuffer_add(dest, outbuf, datalen)  == -1 ) {
    // add uri field
    log_warn("evbuffer_add of uri failed");
    goto clean_up;
  }

  if (evbuffer_add(dest, "HTTP/1.1\r\nHost: ", strlen("HTTP/1.1\r\nHost: "))  == -1) {
    log_warn("evbuffer_add of protocol failed");
    goto clean_up;
  }

  if (evbuffer_add(dest, hostname, strlen(hostname))   == -1) {
    log_warn("evbuffer_add of hostname failed");
    goto clean_up;
  }

  /*
  if (evbuffer_add(dest, s->peer_dnsname, strlen(s->peer_dnsname))   == -1) {
    log_warn("evbuffer_add of host failed");
    goto clean_up;
  }
  */

  
  if (evbuffer_add(dest, accept, strlen(accept))   == -1) {
    log_warn("evbuffer_add of accept failed");
    goto clean_up;
  }
  
  if (evbuffer_add(dest, HTTP_HEADERS_END, strlen(HTTP_HEADERS_END))   == -1) {
    log_warn("evbuffer_add of HTTP_HEADERS_END failed");
    goto clean_up;
  }

  log_debug("%p %p %p", s, dest, source);

  evbuffer_drain(source, source_length);

  conn_do_flush(s->conn);

  s->type = HTTP_CONTENT_MJPEG;
  s->have_transmitted = true;
  s->have_received = false;
  retval = TRANSMIT_GOOD;

 clean_up:
  if (outbuf != NULL)free(outbuf);
  if (data != NULL)free(data);

  return retval;
}


recv_t
stream_server_MJPEG_receive (stream_steg_t * s, struct evbuffer *dest, struct evbuffer *source){
  /* here to stop whining about unused variables sheesh! */
  log_debug("%p %p %p", s, dest, source);
  recv_t retval = RECV_BAD;
  size_t  bytes_decoded = 0, outbuflen = MAX_COOKIE_SIZE * 3 / 2;
  char *outbuf = NULL;

  
  outbuf = (char *)xzalloc(outbuflen);
  
  if(outbuf == NULL){
    log_warn("outbuf allocation failed.");
    goto clean_up;
  }
  
  if (!validate_uri(s->headers_in, s->headers_in_length)) {
    log_warn("invalid uri %s\n", s->headers_in);
    s->conn->expect_close();
    goto clean_up;
  }
  
  
  if (decode_uri(s->headers_in, s->headers_in_length, outbuf, outbuflen, bytes_decoded) != RCODE_OK) {
    log_warn("Failed to decode uri");
    retval = RECV_BAD;
    goto clean_up;
  } 

  if (evbuffer_add(dest, outbuf, bytes_decoded)  == -1) {
    log_warn("Failed to transfer buffer");
    goto clean_up;
  }    

  retval = RECV_GOOD;

 clean_up:
  if(outbuf != NULL) free(outbuf);

  return retval;
}


rcode_t
stream_gen_uri(char* uri, size_t uri_sz, char* data, size_t& datalen)
{
  size_t so_far = 0;

  memset(uri, 0, uri_sz);
  strcat(uri, "GET /");
  so_far = 5;

  while (datalen > 0 && uri_sz - so_far >= 7) {
    unsigned int r = randomg() % 4;

    if (r == 1) {
      r = randomg() % 46;

      if (r < 20)
        uri[so_far++] = 'g' + r;
      else
        uri[so_far++] = 'A' + r - 20;
    }
    else {
      uri[so_far++] = data[0];
      data++;
      datalen--;
    }

    r = randomg() % 8;

    if (r == 0 && datalen > 0)
      uri[so_far++] = '/';

    if (r == 2 && datalen > 0)
      uri[so_far++] = '_';
  }

  if (uri_sz - so_far < 7) {
    log_warn("too small: %" PriSize_t " vs %" PriSize_t, so_far, uri_sz);
    goto err;
  }

  
  if (memncpy(uri+so_far, uri_sz-so_far, ".mjpeg ", 7) != RCODE_OK)
    goto err;

  datalen = strlen(uri);
  return RCODE_OK;
  
 err:
  return RCODE_ERROR;  
}
