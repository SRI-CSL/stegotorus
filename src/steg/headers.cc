/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "headers.h"
#include "base64.h"
#include "strncasestr.h"
#include "b64cookies.h"

#include "oshacks.h"


#include <string.h>

static rcode_t get_header_value(char* headers, size_t headers_length, char** valuep, size_t& value_length, const char* key);

const char* http_content_type_to_string(http_content_t content_type){
  switch(content_type){
  case HTTP_CONTENT_NONE:          return "none";
  case HTTP_CONTENT_JAVASCRIPT:    return "javascript";
  case HTTP_CONTENT_PDF:           return "pdf";
  case HTTP_CONTENT_SWF:           return "flash";
  case HTTP_CONTENT_ENCRYPTEDZIP:  return "zip";
  case HTTP_CONTENT_HTML:          return "html";
  case HTTP_CONTENT_JSON:          return "json";
  case HTTP_CONTENT_JPEG:          return "jpeg";
  case HTTP_CONTENT_RAW:           return "octet-stream";
  default:                         return "unknown";
  }
}


/* Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF */
int
get_http_status_code(char *headers, size_t headers_length){
  int http_code = -1;
  int buffersz =  4;
  char buffer[buffersz];
  char *start = headers;
  char *end = strnstr(start, "\r\n", headers_length); 
  if(end){
    char* sp_one = strchr(start, ' ');
    if(sp_one != NULL){
      char* code = &sp_one[1];
      char* sp_two = strchr(code, ' ');
      if(sp_two != NULL){
        for(int i = 0; i < buffersz; i++){
          char c = code[i];
          if(c != ' '){
            buffer[i] = c;
          } else {
            buffer[i] = '\0';
            http_code = atoi(buffer);
            break;
          }
        }
      } else {
        http_code = -2;
      }
    }
  }
  return  http_code;
}


http_method_t
get_method (char *headers, size_t /* headers_length */)
{
  if(!strncasecmp(headers, "GET ",  sizeof("GET ") - 1)){ return HTTP_GET; }
  if(!strncasecmp(headers, "HEAD ", sizeof("HEAD ") - 1)){ return HTTP_HEAD; }
  if(!strncasecmp(headers, "POST ", sizeof("POST ") - 1)){ return HTTP_POST; }
  return HTTP_UNKNOWN;
}



rcode_t
get_cookie (char *headers, size_t headers_length, char** cookiep, size_t& cookie_length)
{

  char *cstart = NULL, *cend = NULL, *cookie = NULL;
  char cookie_get[] = "Cookie: ";
  char cookie_set[] = "Set-Cookie: ";
  char *cookie_header;
  size_t offset;
  size_t cstart_length;

  cookie_length = 0;
  cookie_header = cookie_get;
  cstart = strncasestr(headers, cookie_header, headers_length);  

  if(cstart == NULL) {
      cookie_header = cookie_set;
      cstart = strncasestr(headers, cookie_header, headers_length);
      if(cstart == NULL) {
        goto err;
      }
  }

  cstart = cstart + strlen(cookie_header);

  /* cstart is a pointer to an address after headers */
  assert(cstart >= headers);
  
  offset = cstart - headers;

  cstart_length =  headers_length - offset;
  cend = strnstr(cstart,"\r\n", cstart_length);
  cookie_length = cend - cstart;
  cookie = (char*)xmalloc(cookie_length + 1);

  if(cookie == NULL){
    log_warn("couldn't make space for cookie");
    goto err;
  }

  if (memncpy(cookie, cookie_length+1, cstart, cookie_length) != RCODE_OK)
    goto err;

  cookie[cookie_length] = '\0';

  if(cookiep != NULL){
    *cookiep = cookie;
    return RCODE_OK;
  } 


 err:
  free(cookie);  
  return RCODE_ERROR;;
}

#define DIGITS  10

rcode_t
get_content_length (char* headers, size_t headers_length, size_t& content_length)
{
  char  *field_start, *field_end, *field_value; 
  size_t digit_count = 0;
  char digits[DIGITS];
  size_t offset;
  size_t field_start_length;

  content_length = 0;
  
  /* can be freewheeling (but won't be); headers is NULL terminated */
  field_start = strncasestr(headers, HTTP_HEADERS_CONTENT_LENGTH, headers_length);

  if (field_start == NULL) {
    log_warn("unable to find content-length in the header");
    return RCODE_ERROR;
  }

  /* cstart is a pointer to an address after headers */
  assert(field_start >= headers);
  
  offset = field_start - headers;
  field_start_length =  headers_length - offset;
  field_end = strnstr(field_start, HTTP_HEADERS_EOL, field_start_length);

  if (field_end == NULL) {
    log_warn("unable to find end of line for \"%s\"", HTTP_HEADERS_CONTENT_LENGTH);
    return RCODE_ERROR;
  }
  
  field_value = field_start + strlen(HTTP_HEADERS_CONTENT_LENGTH);
  digit_count = (field_end - field_value);
  if (digit_count >= DIGITS || digit_count == 0) {
    log_warn("value of content-length field too large or invalid field");
    return RCODE_ERROR;
  }

  if (memncpy(digits, DIGITS, field_value, digit_count) != RCODE_OK)
    return RCODE_ERROR;

  digits[digit_count] = 0;  
  content_length = atoi(digits);  
  return RCODE_OK;
}




static rcode_t
get_header_value(char* headers, size_t headers_length, char** valuep, size_t& value_length, const char* key)
{
  char  *field_start, *field_end, *field_value; 
  size_t field_count = 0;
  bool debug = false;
  size_t offset;
  size_t field_start_length;

  if(key == NULL){
    goto err;
  }

  field_start = strncasestr(headers, key, headers_length);
  if (field_start == NULL) {
    if(debug){ log_warn("unable to find %s in the header", key); }
    return RCODE_FIELD_NOT_FOUND;
  }

  assert(field_start >= headers);
  
  offset = field_start - headers;
  field_start_length =  headers_length - offset;
  
  field_end = strnstr(field_start, HTTP_HEADERS_EOL, field_start_length);
  if (field_end == NULL) {
    if(debug){ log_warn("unable to find end of line for \"%s\"", key); }
    goto err;
  }
  
  field_value = field_start + strlen(key);
  field_count = (field_end - field_value);

  if (field_count > 0) {
    char* field = (char *)xzalloc(field_count + 1);

    if(field != NULL){
      if (memncpy(field, field_count+1, field_value, field_count) != RCODE_OK){
        free(field);
        goto err;
      }

      field[field_count] = '\0';
      if(valuep != NULL){
        *valuep = field;
        value_length = field_count;
	return RCODE_OK;
      } else {
        free(field);
      }
    }
  }
  return RCODE_OK;

 err:
  return RCODE_ERROR;
}


rcode_t
get_accept (char* headers, size_t headers_length, char** acceptp, size_t& vlength)
{
  return get_header_value(headers, headers_length, acceptp, vlength, HTTP_HEADERS_ACCEPT);
}

rcode_t
get_accept_encoding(char* headers, size_t headers_length, char** encodingp, size_t& vlength)
{
  return get_header_value(headers, headers_length, encodingp, vlength, HTTP_HEADERS_ACCEPT_ENCODING);
}
  
rcode_t
get_content_encoding(char* headers, size_t headers_length, char** encodingp, size_t& vlength)
{
  return get_header_value(headers, headers_length, encodingp, vlength, HTTP_HEADERS_CONTENT_ENCODING);
}
  
rcode_t
get_content_type(char* headers, size_t headers_length, char** typep, size_t& vlength)
{
  return get_header_value(headers, headers_length, typep, vlength, HTTP_HEADERS_CONTENT_TYPE);
}
  

bool
is_gzip_encoded(char *headers, size_t headers_length)
{
  char* encoding = NULL;
  size_t encoding_length = 0; 
  bool retval = false;

  if (get_content_encoding(headers, headers_length, &encoding, encoding_length) == RCODE_ERROR) 
    log_warn("something went wrong in get_content_encoding");

  if((encoding_length >= (int) sizeof("gzip") - 1) && (encoding != NULL) && (strcmp(encoding, "gzip") == 0)){
    retval = true;
  } else {
    retval = false; 
  }
  free(encoding);
  return retval;
}

/* the default is false; currently we just say yes if it looks like the jumpbox  */
bool will_accept_gzip(char *headers, size_t headers_length)
{
  char* accept = NULL;
  bool retval = false, debug = false;
  size_t accept_length;
  char* encoding = NULL;
  size_t encoding_length = 0;

  if (get_accept(headers, headers_length, &accept, accept_length) == RCODE_ERROR)
    log_warn("something went wrong in get_accept");

  if(accept_length == 0){
    if(debug){ log_warn("Accept: %s", accept); }
  } else {
    if(debug){ log_warn("Accept missing"); }
  }
  

  // should we propogate errors here?
  if (get_accept_encoding(headers, headers_length, &encoding, encoding_length) == RCODE_ERROR) {
    log_warn("something went wrong in get_accept_encoding");
  }
    
  if(encoding_length == 0){
    if(debug){ log_warn("Encoding: %s", encoding); }
  } else {
    if(debug){ log_warn("Encoding missing"); }
  }
  
  retval = (encoding != NULL) && (strcmp(encoding, "gzip,deflate,sdch") == 0);

  free(accept);
  free(encoding);

  
  return retval;
  
}


/*
 * find_content_type(char *headers, size_t headers_length)
 *
 * If the HTTP header of msg specifies that the content type:
 * case (content type)
 *   javascript: return HTTP_CONTENT_JAVASCRIPT
 *   pdf:        return HTTP_CONTENT_PDF
 *   shockwave:  return HTTP_CONTENT_SWF
 *   html:       return HTTP_CONTENT_HTML
 *   json:       return HTTP_CONTENT_JSON
 *   jpeg:       return HTTP_CONTENT_JPEG
 *   otherwise:  return 0
 *
 * Assumptions:
 * headers is null terminated
 *
 * Recent Changes:  is now case insensitive (iam) 
 */
http_content_t
find_content_type (char *headers, size_t headers_length)
{
  char *ptr = headers, *end;

  if(headers == NULL)
    return HTTP_CONTENT_NONE;

    
  if (!strnstr(headers, "\r\n\r\n", headers_length)) {
    return HTTP_CONTENT_NONE;
  }
  // need to polish from here on

  while (1) {
    size_t offset = ptr - headers;
    size_t ptr_length = headers_length - offset;
    
    end = strnstr(ptr, "\r\n", ptr_length);
    if (end == NULL) {
      break;
    }

    if (!strncasecmp(ptr, "content-type:", 13)) {

      if (!strncasecmp(ptr+14, "text/javascript", 15) ||
          !strncasecmp(ptr+14, "application/javascript", 22) ||
          !strncasecmp(ptr+14, "application/x-javascript", 24)) {
        return HTTP_CONTENT_JAVASCRIPT;
      }
      if (!strncasecmp(ptr+14, "text/html", 9)) {
        return HTTP_CONTENT_HTML;
      }
      if (!strncasecmp(ptr+14, "application/pdf", 15) ||
          !strncasecmp(ptr+14, "application/x-pdf", 17)) {
        return HTTP_CONTENT_PDF;
      }
      if (!strncasecmp(ptr+14, "application/x-shockwave-flash", sizeof("application/x-shockwave-flash") - 1)) {
        return HTTP_CONTENT_SWF;
      }
      if (!strncasecmp(ptr+14, "application/json", 16)) {
        return HTTP_CONTENT_JSON;
      }
      if (!strncasecmp(ptr+14, "image/jpeg", 10)) {
        return HTTP_CONTENT_JPEG;
      }
      if (!strncasecmp(ptr+14, "application/octet-stream", 24)) {
        return HTTP_CONTENT_RAW;
      }
    }

    if (!strncasecmp(end, "\r\n\r\n", 4)){
      break;
    }
    ptr = end+2;
  }

  return HTTP_CONTENT_NONE;
}


//rcode encode_cookie (const char* data, size_t data_length, char* &cookiep, size_t& cookie_szp)

rcode_t
encode_cookie (const char* data, size_t data_length, char** cookiep, size_t& cookie_length)
{
  size_t len = 0, dlen = data_length * 4, clen = data_length * 8;
  char *data64 = (char*)xzalloc(dlen);
  char  *cookie = (char*)xzalloc(clen);
  // '+' -> '-', '/' -> '_', '=' -> '.' per
  // RFC4648 "Base 64 encoding with URL and filename safe alphabet"
  // (which does not replace '=', but dot is an obvious choice; for
  // this use case, the fact that some file systems don't allow more
  // than one dot in a filename is irrelevant).

  base64::encoder E(false, '-', '_', '.');

  cookie_length = 0;
  len  = E.encode(data, data_length, data64);
  len += E.encode_end(data64+len);
  data64[len] = '\0';

  //strip off the trailing .'s
  while (len > 0 && data64[len - 1] == '.'){
    data64[--len] = '\0';
  }

  if (gen_b64_cookies(cookie, clen, data64, len, cookie_length) != RCODE_OK)
    goto err;

  cookie[cookie_length] = '\0';
  *cookiep = cookie;
  free(data64);  
  return RCODE_OK;

 err:
  log_warn("encode_cookie failed");
  free(data64);
  free(cookie);
  return RCODE_ERROR;
}


rcode_t
decode_cookie (const char* cookie, size_t cookie_length, char* out_buffer, size_t& sofar)
{
  /* not my idea */
  size_t outbuf_length = (MAX_COOKIE_SIZE * 3)/2;
  char* outbuf = (char *)xzalloc(outbuf_length);
  base64::decoder D('-', '_');
  size_t cookielen = 0, decodelen = 0;  
  rcode_t retval = RCODE_ERROR;

  log_debug("Cookie: %s", cookie);
  sofar = 0;
  
  if (cookie_length > outbuf_length){
    log_warn("cookie too big: %" PriSize_t "(max %" PriSize_t ")", cookie_length, (size_t)MAX_COOKIE_SIZE);
    goto clean_up;
  }
  
  if (unwrap_b64_cookies(outbuf, outbuf_length, cookie, cookie_length, cookielen) != RCODE_OK)
    goto clean_up;

  while (cookielen % 3 != 0)
    outbuf[cookielen++] = '.';

  decodelen = D.decode(outbuf, cookielen+1, out_buffer);
  
  if (decodelen <= 0){
    log_warn("base64 decode failed\n");
    goto clean_up;
  }
  
  sofar = (unsigned int) decodelen;
  
  if (sofar >= MAX_COOKIE_SIZE){
    log_warn("cookie decode buffer overflow");
    goto clean_up;
  }

  retval = RCODE_OK;
  
 clean_up:
  if(retval != RCODE_OK){
    log_warn("cookie bad: %" PriSize_t, cookie_length);
  }

  if (outbuf != NULL)
    free(outbuf);

  return retval;
}


rcode_t
decode_uri (char *headers, size_t  /* headers_length */, char* out_buffer, size_t outbuflen, 
	    size_t& bytes_written)
{
  unsigned char c, h, secondhalf;
  size_t sofar = 0;
  char *p = headers + sizeof "GET /" - 1;
  secondhalf = 0;
  c = 0;
    
  while (strncmp((char*) p, "\r\n", 2) != 0 && (p[0] != '.') && sofar < MAX_COOKIE_SIZE) {
    if (!secondhalf)
      c = 0;
    if ('0' <= *p && *p <= '9')
      h = *p - '0';
    else if ('a' <= *p && *p <= 'f')
      h = *p - 'a' + 10;
    else {
      p++;
      continue;
    }
    
    c = (c << 4) + h;
    if (secondhalf) {
      if (sofar >= outbuflen) {
	log_warn("decode_uri: outbuf too small");
	return RCODE_ERROR;
      }
      out_buffer[sofar++] = c;
    }
    secondhalf = !secondhalf;
    p++;
  }
  
  if (sofar >= (MAX_COOKIE_SIZE-1)) {
    log_warn("data in uri too long: incorrect recovery");
    return RCODE_ERROR;
  }
  
  out_buffer[sofar] = 0;
  
  if (secondhalf) {
    log_warn("incorrect uri recovery");
    return RCODE_ERROR;
  }
  
  bytes_written = sofar;
  return RCODE_OK;
}

