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


static recv_t
http_server_receive_POST (http_steg_t * s, struct evbuffer *dest, struct evbuffer* source, char* headers, size_t headers_length);

static recv_t
http_server_receive_GET (http_steg_t * s, struct evbuffer *dest, struct evbuffer* source, char* headers, size_t headers_length);

static recv_t
http_server_receive_HEAD (http_steg_t * /* s */, struct evbuffer * /* dest */, struct evbuffer* /* source */ , char* /* headers */, size_t /* headers_length */);


transmit_t
http_server_transmit (http_steg_t * s, struct evbuffer *source)
{
  transmit_t retval = NOT_TRANSMITTED;

  switch(s->type) {
  case HTTP_CONTENT_SWF: {
    retval = http_server_SWF_transmit(s->config->pl, source, s->conn);
    break;
  }
  case HTTP_CONTENT_JAVASCRIPT:
    retval = http_server_JS_transmit (s, source, HTTP_CONTENT_JAVASCRIPT);
    break;
    
  case HTTP_CONTENT_HTML:
    retval = http_server_JS_transmit (s, source, HTTP_CONTENT_HTML);
    break;
    
  case HTTP_CONTENT_PDF:
    retval = http_server_PDF_transmit(s, source);
    break;
    
  case HTTP_CONTENT_JSON:
    retval = http_server_JSON_transmit(s, source);
    break;
  
  case HTTP_CONTENT_JPEG:
    retval = http_server_JPEG_transmit(s, source);
    break;

  case HTTP_CONTENT_RAW:
    retval = http_server_RAW_transmit(s, source);
    break;

  default:
    break;
  }
  
  if (retval == TRANSMIT_GOOD) {
    s->have_transmitted = true;
    s->have_received = false;
    if(!s->persist_mode){
      s->conn->cease_transmission();
    } else {
      conn_do_flush(s->conn);
    }
  }
  
  return retval;
}

recv_t
http_server_receive (http_steg_t *s, struct evbuffer *dest, struct evbuffer* source, char *headers, size_t headers_length)
{
  recv_t retval = RECV_BAD;
  http_method_t method = HTTP_UNKNOWN;


#ifdef ST_SHOWURI
  fprintf(stderr, "server headers: %s\n", headers);
#endif

  /* switch on method before anything else */
  method = get_method(headers, headers_length);


  switch(method){
  case HTTP_POST: {
    /* http_server_receive_POST sets s->type */
    retval = http_server_receive_POST(s, dest, source, headers, headers_length);
    if(!post_reflection && retval == RECV_GOOD){
      s->type = HTTP_CONTENT_HTML;
    }
    break;
  }
  case HTTP_GET: {
    /* http_server_receive_GET sets s->type */
    retval =  http_server_receive_GET(s, dest, source, headers, headers_length);
    break;
  }
  case HTTP_HEAD: {
    retval =  http_server_receive_HEAD(s, dest, source, headers, headers_length);
    s->type = HTTP_CONTENT_HTML;
    break;
  }
  default:
    log_warn("Got an UNKNOWN METHOD: %s", headers);
    /* This is up for debate / testing */
    retval = RECV_BAD;
    goto clean_up;
  }

  if(retval == RECV_BAD){
    log_warn("http_server_receive retval = %d type = %d method = %d", retval, s->type, method);
    goto clean_up;
  }

  /* don't flip this switch if we haven't received! */
  if(retval != RECV_INCOMPLETE){
    s->have_received = true;
  }

  
  //s->type = type;

  if(!s->persist_mode && retval != RECV_INCOMPLETE){
    s->conn->expect_close();
  } else {
    conn_do_flush(s->conn);
  }
   
  s->conn->transmit_soon(100);

  if(s->persist_mode){    
    s->have_transmitted = false;
  }

 clean_up:
  //log_warn("http_server_receive retval = %d type = %d method = %d", retval, s->type, method);
  return retval;
}



static recv_t
http_server_receive_POST (http_steg_t * s, struct evbuffer *dest, struct evbuffer* source, char* headers, size_t headers_length)
{
  recv_t rval = RECV_BAD;
  char *request = NULL; 
  size_t request_length;
  http_content_t type_on_wire, rtype = HTTP_CONTENT_NONE;

  if (peek_content(source, headers_length, headers, &request, request_length) != RCODE_OK)
    return RECV_INCOMPLETE;

  /* we should check that the content type matches the local type */
  type_on_wire = find_content_type(headers, headers_length);

  if(type_on_wire == HTTP_CONTENT_JSON){
    rtype =  HTTP_CONTENT_JSON;
  } else if(type_on_wire == HTTP_CONTENT_JPEG){
    rtype =  HTTP_CONTENT_JPEG;
  } else if(type_on_wire == HTTP_CONTENT_RAW){
    rtype =  HTTP_CONTENT_RAW;
  } else if(type_on_wire == HTTP_CONTENT_PDF){
    rtype =  HTTP_CONTENT_PDF;
  }

  s->type = rtype; 

  switch(rtype){
  case HTTP_CONTENT_JSON:
    rval = http_server_JSON_post_receive(s, dest, headers, headers_length, request, request_length);
    break;

  case HTTP_CONTENT_JPEG:
    rval = http_server_JPEG_post_receive(s, dest, headers, headers_length, request, request_length);
    break;

  case HTTP_CONTENT_PDF:
    rval = http_server_PDF_post_receive(s, dest, headers, headers_length, request, request_length);
    break;

  case HTTP_CONTENT_RAW:
    rval = http_server_RAW_post_receive(s, dest, headers, headers_length, request, request_length);
    break;

  default:
    log_warn("http_server_receive: UNKNOWN POST type:  %s", http_content_type_to_string(type_on_wire));
    break;
    
  }

  if (evbuffer_drain(source, request_length) == -1) {
    log_warn("failed to drain source");
  } 

  if(request != NULL){ free(request); }
  
  return rval;
}


static recv_t
http_server_receive_GET (http_steg_t * s, struct evbuffer *dest, struct evbuffer* source, char* headers, size_t headers_length)
{
  recv_t retval = RECV_BAD;
  char *cookie = NULL, *outbuf = NULL, *outbuf2 = NULL; 
  http_content_t type;
  size_t cookie_length = 0;
  size_t bytes_decoded = 0;
  size_t outbuflen = MAX_COOKIE_SIZE * 3 / 2;
  size_t outbuf2len = MAX_COOKIE_SIZE;

  outbuf = (char *)xzalloc(outbuflen);
  outbuf2 = (char *)xzalloc(outbuf2len);

  if((outbuf == NULL) || (outbuf2 == NULL)){
    log_warn("outbuf allocation failed.");
    goto clean_up;
  }

  if (!validate_uri((char *) headers, headers_length)) {
    log_warn("invalid uri %s\n", headers);
    s->conn->expect_close();
    return RECV_BAD;
  }

  type = find_uri_type(headers, headers_length);
  if(type == HTTP_CONTENT_NONE){
    log_warn("invalid uri type...");
    log_warn("trying to send html");
    s->type = HTTP_CONTENT_HTML;
  } else {
    if(SCHEMES_DEBUG){ log_warn("valid uri type: %s", http_content_type_to_string(type)); }
    s->type = type;
  }

  //log_warn("http_server_receive_GET: headers = %s", headers);

  
  if(get_cookie(headers, headers_length, &cookie, cookie_length) == RCODE_OK) {
    /* COOKIE MODE */    
    if (decode_cookie(cookie, cookie_length, outbuf2, bytes_decoded) != RCODE_OK) {
      log_warn("Failed to decode cookie");
      log_warn("<headers>\n%s\n</headers>", headers);
      goto clean_up;
    }
    
    if (evbuffer_add(dest, outbuf2, bytes_decoded)  == -1) {
      log_warn("Failed to transfer buffer");
      goto clean_up;
    }
    
    evbuffer_drain(source, headers_length);
    
  } 
  else {     /* URI MODE */      

    if (decode_uri(headers, headers_length, outbuf, outbuflen, bytes_decoded) != RCODE_OK) {
      log_warn("Failed to decode uri");
      retval = RECV_BAD;
      goto clean_up;
    } 

    evbuffer_drain(source, headers_length);

    if (evbuffer_add(dest, outbuf, bytes_decoded)  == -1) {
      log_warn("Failed to transfer buffer");
      goto clean_up;
    }    
  }

  retval = RECV_GOOD;

 clean_up:
  if(outbuf != NULL) free(outbuf);
  if(outbuf2 != NULL) free(outbuf2);
  if(cookie != NULL) free(cookie);
  //log_warn("http_server_receive_GET: returning %d", retval);

  return retval;
}

static recv_t
http_server_receive_HEAD (http_steg_t * /* s */, struct evbuffer * /* dest */, struct evbuffer* /* source */ , char* /* headers */, size_t /* headers_length */)
{
  recv_t retval = RECV_BAD;
  /*
    XYZ: The HEAD method is identical to GET except that the server MUST NOT return a message-body in the response.
    The metainformation contained in the HTTP headers in response to a HEAD request SHOULD be identical to
    the information sent in response to a GET request.
  */
  return retval;
}


