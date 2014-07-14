#include "http_client.h"

#include "swfSteg.h"
#include "pdfSteg.h"
#include "jsSteg.h"
#include "jsonSteg.h"
#include "jpegSteg.h"
#include "rawSteg.h"
#include "b64cookies.h"
#include "shared.h"
#include "headers.h"

#include "schemes.h"
#include "strncasestr.h"

#include "oshacks.h"


static transmit_t
http_client_uri_transmit (http_steg_t *s, struct evbuffer *source, conn_t *conn);

static transmit_t
http_client_cookie_transmit (http_steg_t *s, struct evbuffer *source, conn_t *conn);

transmit_t
http_client_transmit (http_steg_t * s, struct evbuffer *source)
{
  transmit_t retval = NOT_TRANSMITTED;
  size_t room  = evbuffer_get_length(source);
  int scheme = schemes_get_transmit_scheme(room);

  if (SCHEMES_DEBUG){ log_warn("<http_client_transmit:%" PriSize_t">\n%s", room, schemes_to_string(scheme)); }

  switch(scheme){
  case -1: {
    log_warn("no scheme available");
    break;
  }
  case COOKIE_TRANSMIT: {
    retval = http_client_cookie_transmit(s, source, s->conn);
    break;
  }
  case URI_TRANSMIT: {
    retval = http_client_uri_transmit(s, source, s->conn);
    break;
  }
  case JSON_POST: {
    retval = http_client_JSON_post_transmit(s, source, s->conn);
    if(!post_reflection && retval == TRANSMIT_GOOD){
      s->type = HTTP_CONTENT_HTML;
    }
    break;
  }
  case JPEG_POST: {
    retval = http_client_JPEG_post_transmit(s, source, s->conn);
    if(!post_reflection && retval == TRANSMIT_GOOD){
      s->type = HTTP_CONTENT_HTML;
    }
    break;
  }
  case PDF_POST: {
    retval = http_client_PDF_post_transmit(s, source, s->conn);
    if(!post_reflection && retval == TRANSMIT_GOOD){
      s->type = HTTP_CONTENT_HTML;
    }
    break;
  }
  case RAW_POST: {
    retval = http_client_RAW_post_transmit(s, source, s->conn);
    if(!post_reflection && retval == TRANSMIT_GOOD){
      s->type = HTTP_CONTENT_HTML;
    }
    break;
  }
  default: {
    log_warn("mystery scheme %d", scheme);
    break;
  }
  }

  if (SCHEMES_DEBUG){ log_warn("</http_client_transmit>"); }
  return retval;
}




recv_t
http_client_receive(http_steg_t * s, struct evbuffer * dest, struct evbuffer* source, char *headers, size_t headers_length)
{
  int headers_debug = 0;
  recv_t rval = RECV_BAD;
  char *response = NULL; 
  size_t response_length; 
  http_content_t type_on_wire, rtype;


  if (headers_debug){
    log_warn("http_client_receive: headers_length = %" PriSize_t, headers_length);
    log_warn("http_client_receive: <headers>\n%s</headers> ", headers);
  }

  /* see if we are ready to process the response */

  if (peek_content(source, headers_length, headers, &response, response_length) != RCODE_OK) {
    log_debug("Failed to get all of the response");
    return RECV_INCOMPLETE;
  }
    
  /* we should check that the content type matches the local type */
  type_on_wire = find_content_type(headers, headers_length);
  
  if (type_on_wire != s->type){
    log_warn("http_client_receive: s->type      = %s", http_content_type_to_string(s->type));
    log_warn("http_client_receive: type_on_wire = %s", http_content_type_to_string(type_on_wire));
    log_warn("<headers>\n%s\n</headers>\n", headers);
  }
  
  rtype = s->type;

  if (type_on_wire == HTTP_CONTENT_JSON){
    rtype =  HTTP_CONTENT_JSON;
  } else if (type_on_wire == HTTP_CONTENT_JPEG){
    rtype =  HTTP_CONTENT_JPEG;
  } else if (type_on_wire == HTTP_CONTENT_RAW){
    rtype =  HTTP_CONTENT_RAW;
  }

  s->type = rtype; 

  switch(rtype) {
  case HTTP_CONTENT_SWF:
    rval = http_client_SWF_receive(s, dest, headers, headers_length, response, response_length);
    break;
    
  case HTTP_CONTENT_JAVASCRIPT:
  case HTTP_CONTENT_HTML:
    rval = http_client_JS_receive(s, dest, headers, headers_length, response, response_length);
    break;
    
  case HTTP_CONTENT_PDF:
    rval = http_client_PDF_receive(s, dest, headers, headers_length, response, response_length);
    break;
    
  case HTTP_CONTENT_JSON:
    rval = http_client_JSON_receive(s, dest, headers, headers_length, response, response_length);
    break;

  case HTTP_CONTENT_JPEG:
    rval = http_client_JPEG_receive(s, dest, headers, headers_length, response, response_length);
    break;
    
  case HTTP_CONTENT_RAW:
    rval = http_client_RAW_receive(s, dest, headers, headers_length, response, response_length);
    break;

  default:
    break;
  }
  
  if (evbuffer_drain(source, response_length) == -1) {
    log_warn("failed to drain source");
  } 

  if (response != NULL){ free(response); }
  
  return rval;
}




static transmit_t
http_client_cookie_transmit (http_steg_t *s, struct evbuffer *source, conn_t *conn)
{
  int rval;
  transmit_t retval = NOT_TRANSMITTED;
  struct evbuffer *dest = conn->outbound();
  size_t sbuflen = evbuffer_get_length(source);
  size_t bufsize = 10*1024;
  char* buf = (char*) xmalloc(bufsize), *data = NULL, *cookie = NULL, *eol = NULL;
  size_t payload_len = 0, cnt = 0, cookie_len = 0;
  size_t offset;
  http_content_t payload_type = HTTP_CONTENT_NONE;
  
  data = (char*) evbuffer_pullup(source, sbuflen);
  if (!data) {
    log_debug("evbuffer_pullup failed");
    goto clean_up;
  }

  // retry up to 10 times
  while (!payload_len) {
    if (find_client_payload(s->config->pl, buf, bufsize, TYPE_HTTP_REQUEST, payload_len) != RCODE_OK)
      continue;

    payload_type = find_uri_type(buf, bufsize);
    if (payload_type <= 0 || !schemes_is_enabled(payload_type) || !schemes_is_usable(payload_type)) {
      if (SCHEMES_DEBUG){
        log_warn("SKIPPING: %s", http_content_type_to_string(payload_type));
      }
      payload_len = 0;
      payload_type = HTTP_CONTENT_NONE;
      continue;
    }
    if (cnt++ == 10) {
      goto clean_up;
    }
    if (SCHEMES_DEBUG){ log_warn("USING: %s", http_content_type_to_string(payload_type)); }
  }

  buf[payload_len] = 0;

#ifdef ST_SHOWURI
  fprintf(stderr, "Cookie-URI: %s\n", buf);
#endif

  if (s->peer_dnsname[0] == '\0')
    lookup_peer_name_from_ip(conn->peername, s->peer_dnsname, sizeof(s->peer_dnsname));

  if (encode_cookie(data, sbuflen, &cookie, cookie_len) != RCODE_OK)
    goto clean_up;

  if (perturb_uri(buf, payload_len) < 0) {
    log_warn("perturb_uri failed %s", buf);
  }

  // add uri field
  rval = evbuffer_add(dest, buf, strnstr(buf, "\r\n", payload_len) - buf + 2);
  if (rval == -1) {
    log_warn("error adding uri field");
    goto clean_up;
  }

  rval = evbuffer_add(dest, "Host: ", 6);
  if (rval == -1) {
    log_warn("error adding host field");
    goto clean_up;
  }

  rval = evbuffer_add(dest, s->peer_dnsname, strlen(s->peer_dnsname));
  if (rval == -1) {
    log_warn("error adding peername field");
    goto clean_up;
  }

  eol = strnstr(buf, "\r\n", payload_len);
  if (eol == NULL){
    log_warn("no eol found");
    goto clean_up;

  }

  offset = eol - buf;
  rval = evbuffer_add(dest, eol, payload_len - offset);
  if (rval == -1) {
    log_warn("error adding HTTP fields");
    goto clean_up;
  }

  rval =   evbuffer_add(dest, "Cookie: ", 8);
  if (rval == -1) {
    log_warn("error adding cookie fields");
    goto clean_up;
  }

  rval = evbuffer_add(dest, cookie, cookie_len);
  if (rval == -1) {
    log_warn("error adding cookie buf");
    goto clean_up;
  }

  rval = evbuffer_add(dest, "\r\n\r\n", 4);
  if (rval == -1) {
    log_warn("error adding terminators");
    goto clean_up;
  }

  evbuffer_drain(source, sbuflen);
  s->have_transmitted = true;
  s->have_received = false;

  if (!s->persist_mode){
    conn->cease_transmission();
  } else {
    conn_do_flush(conn);
  }

  s->type = find_uri_type(buf, bufsize);

  if (payload_type != s->type) {
    log_warn("http_client_transmit: s->type      = %s", http_content_type_to_string(s->type));
    log_warn("http_client_transmit: payload_type = %s", http_content_type_to_string(payload_type));
  }

  retval = TRANSMIT_GOOD;

 clean_up:
  free(cookie);
  free(buf);
  return retval;
}



static transmit_t
http_client_uri_transmit (http_steg_t *s, struct evbuffer *source, conn_t *conn)
{
  transmit_t retval = NOT_TRANSMITTED;
  size_t len = 0, cnt = 0;
  struct evbuffer *dest = conn->outbound();
  size_t source_length = evbuffer_get_length(source);
  char *data = NULL, *outbuf = NULL, *buf = NULL, *eol = NULL;
  size_t datalen = 0;
  size_t outbufsz = 3*1024;
  size_t bufsz = 10*1024;
  size_t offset = 0;

  if (source2hex(source, source_length, &data, datalen) != RCODE_OK) {
    log_warn("source2hex called returned negative value");
    goto clean_up;
  }

  outbuf = (char *)xzalloc(outbufsz);
  buf = (char *)xzalloc(bufsz);

  if ((outbuf == NULL) || (buf == NULL)) {
    log_warn("outbuf allocation failed.");
    goto clean_up;
  }

  if (s->peer_dnsname[0] == '\0')
    lookup_peer_name_from_ip(conn->peername, s->peer_dnsname, sizeof(s->peer_dnsname));

  // loop till success
  while (schemes_gen_uri_field(outbuf, outbufsz, data, datalen) != RCODE_OK){ };

  if (SCHEMES_DEBUG) { 
    http_content_t payload_type = find_uri_type(outbuf, outbufsz);
    log_warn("USING: %s", http_content_type_to_string(payload_type));
  }

#ifdef ST_SHOWURI
  fprintf(stderr, "URI: %s\n", outbuf);
#endif

  // retry up to 10 times
  while (!len && cnt++ < 10) {
    if (find_client_payload(s->config->pl, buf, bufsz, TYPE_HTTP_REQUEST, len) != RCODE_OK)
      continue;
  }
  
  if (len == 0)
    goto clean_up;

  if (evbuffer_add(dest, outbuf, datalen)  == -1 ) {
    // add uri field
    log_warn("evbuffer_add of uri failed");
    goto clean_up;
  }

  if (evbuffer_add(dest, "HTTP/1.1\r\nHost: ", strlen("HTTP/1.1\r\nHost: "))  == -1) {
    log_warn("evbuffer_add of protocol failed");
    goto clean_up;
  }

  if (evbuffer_add(dest, s->peer_dnsname, strlen(s->peer_dnsname))   == -1) {
    log_warn("evbuffer_add of host failed");
    goto clean_up;
  }

  eol = strnstr(buf, "\r\n", len);

  if (eol == NULL) {
    log_warn("no eol found");
    goto clean_up;
  }
  offset = eol - buf;

  if (evbuffer_add(dest, eol, len - offset) == -1) {
    log_warn("no eol found");
    goto clean_up;
  }
  
  if (evbuffer_add(dest, "\r\n", 2)  == -1) {
    log_debug("evbuffer_add of \\r\\n failed");
    goto clean_up;
  }

  evbuffer_drain(source, source_length);

  if (!s->persist_mode) {
    conn->cease_transmission();
  } else {
    conn_do_flush(conn);
  }
  s->type = find_uri_type(outbuf, outbufsz);
  s->have_transmitted = true;
  s->have_received = false;
  retval = TRANSMIT_GOOD;

 clean_up:
  if (outbuf != NULL)free(outbuf);
  if (buf != NULL)free(buf);
  if (data != NULL)free(data);

  return retval;
}







