/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */



#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <event2/buffer.h>

#include "oshacks.h"

#include "util.h"
#include "payloads.h"
#include "shared.h"
#include "headers.h"
#include "compression.h"
#include "protocol.h"
#include "strncasestr.h"


static 
char *get_response_aux(struct evbuffer *source, size_t response_length);


rcode_t
source2hex(struct evbuffer *source, size_t source_length, char **datap, size_t& data_length)
{
  
  char* data = NULL;
  unsigned int cnt = 0;
  struct evbuffer_iovec *iv = NULL;
  int nv, i;

  data_length = 0;

  if(datap == NULL){
    log_warn("bad args");
    goto err;
  } 
  
  data  = (char*)xzalloc((2*source_length) + 1);
  
  if(data == NULL){
    log_warn("xmalloc fails for data");
    goto err;
  } 
  
  /* determine how many chunks we need */
  nv = evbuffer_peek(source, source_length, NULL, NULL, 0);
  /* allocate the chunks */
  iv = (evbuffer_iovec *)xzalloc(sizeof(struct evbuffer_iovec) * nv);
  
  if(iv == NULL){
    log_warn("xzalloc fails for iv");
    goto err;
  }

  /* fill up the iv with the chunks */
  if (evbuffer_peek(source, source_length, NULL, iv, nv) != nv) {
    log_warn("evbuffer_peek fails for nv");
    goto err;
  }

  /* convert the chunks in iv to hexadecimal and write it to data  */
  for (i = 0; i < nv; i++) {
    const uchar *p = (const uchar *)iv[i].iov_base;
    const uchar *limit = p + iv[i].iov_len;
    char c;
    while (p < limit && cnt < source_length) {
      c = *p++;
      data[data_length] = "0123456789abcdef"[(c & 0xF0) >> 4];
      data[data_length+1] = "0123456789abcdef"[(c & 0x0F) >> 0];
      data_length += 2;
      cnt++;
    }
    /* make sure the data is NULL terminated (helps with debugging) */
    data[data_length] = '\0';
  }

  *datap = data;

  if (iv != NULL)    
    free(iv);

  return RCODE_OK;

 err:
  if (iv != NULL)    
    free(iv);
  if (data != NULL)
    free(data);

  return RCODE_ERROR;
}



recv_t
hex2dest(struct evbuffer *dest,  size_t data_length, char *data)
{
  recv_t retval = RECV_BAD;
  struct evbuffer *scratch = NULL;
  int k, addcode;
  size_t i, j;
  char c;

  if((data_length == 0)|| (data_length % 2)){
    log_warn("zero or an odd number of hex characters received\n");
    goto clean_up;
  }
  
  if (!is_hex_string(data, data_length)) {
    log_warn("Data received not hex");
    goto clean_up;
  }
  
  /* get a scratch buffer */
  scratch = evbuffer_new();
  if (!scratch){
    goto clean_up;
  }
  
  /* make room for the hex data */
  if (evbuffer_expand(scratch, data_length/2)) {
    log_warn("evbuffer expand failed \n");
    goto clean_up;
  }
  
  /* convert hex data back to binary  */
  for (i = 0, j = 0; i < data_length; i = i + 2, ++j) {
    sscanf(&data[i], "%2x", (unsigned int*) &k);
    c = (char)k;
    addcode = evbuffer_add(scratch, &c, 1);
    if(addcode == -1){
      log_warn("evbuffer_add failed");
      goto clean_up;
    }
  }

  /* add the scratch buffer (which contains the data) to dest */
  addcode = evbuffer_add_buffer(dest, scratch);

  if (addcode == -1) {
    log_warn("evbuffer_add failed");
    goto clean_up;
  }

  retval = RECV_GOOD;

 clean_up:

  if(scratch != NULL){ evbuffer_free(scratch); }

  return retval;

}

rcode_t
source2raw(struct evbuffer *source, size_t source_length, uchar **datap, size_t& data_length)
{

  uchar* data = NULL;
  struct evbuffer_iovec *iv = NULL;
  int nv=0, i=0, offset=0;

  
  if(datap == NULL) {
    log_warn("bad args");
    goto err;
  } 

  data = (uchar*)xzalloc(source_length);
   
  /* ian says: why aren't we using evbuffer_remove? here? */
  if(data == NULL){
    log_warn("xmalloc fails for data");
    goto err;
  } 
  
  /* determine how many chunks we need */
  nv = evbuffer_peek(source, source_length, NULL, NULL, 0);
  /* allocate the chunks */
  iv = (evbuffer_iovec *)xzalloc(sizeof(struct evbuffer_iovec) * nv);
  
  if(iv == NULL){
    log_warn("xzalloc fails for iv");
    goto err;
  }
  
  /* fill up the iv with the chunks */
  if (evbuffer_peek(source, source_length, NULL, iv, nv) != nv) {
    log_warn("evbuffer_peek fails for nv");
    goto err;
  }
     
  /* convert the chunks in iv to hexadecimal and write it to data  */
  for (i = 0; i < nv; i++) {
    size_t len = iv[i].iov_len;
    
    if (memncpy(&data[offset], source_length-offset, iv[i].iov_base, len) != RCODE_OK)
      goto err;
    
    offset += len;
  }
  
  if (iv != NULL)
    free(iv);

  *datap = data;
  data_length = source_length;  
  return RCODE_OK;
  
 err:
  if (data != NULL) free(data);
  if (iv != NULL) free(iv);
  return RCODE_ERROR;
}


recv_t
raw2dest(struct evbuffer *dest, size_t data_length, uchar *data)
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
  
  /* make room for the hex data */
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



/*
  sets the headers and headers length and returns RECV_GOOD upon success,
  RECV_INCOMPLETE if they are NOT all in yet, or RECV_BAD on failure;
  allocs and copies a NULL terminated copy of the headers to headersp!
  leaves everything on the source evbuffer
*/

recv_t
peek_headers(struct evbuffer *source, char **headersp, size_t& headers_length)
{
  struct evbuffer_ptr s2;
  char  *headers = NULL;
  ev_ssize_t bytes_copied;
  recv_t retcode = RECV_BAD;

  headers_length = 0;
  s2 = evbuffer_search(source, HTTP_HEADERS_END, strlen(HTTP_HEADERS_END), NULL);

  if (s2.pos == -1) {
    size_t incoming = evbuffer_get_length(source);
    if(incoming >= DOS_ALERT_SIZE){
      log_warn("headers too big for comfort; FAILING");
      retcode = RECV_BAD;
    } else {
      log_info("Did not find end of HTTP headers %" PriSize_t, incoming);
      retcode = RECV_INCOMPLETE;
    }
    goto clean_up;
  }

  headers_length = (size_t) s2.pos + strlen(HTTP_HEADERS_END);

  /* being careful here, since we don't seem to be promised NULL termination by evbuffer_pullup */
  headers = (char*)xmalloc(headers_length + 1);

  /* get headers  */
  bytes_copied = evbuffer_copyout(source, headers, headers_length);
  if(bytes_copied == -1){
    log_warn("peek_headers: evbuffer_copyout FAILED");
    headers_length = -1;
  } else if ((size_t) bytes_copied != headers_length) {
    log_warn("unable to pullup the complete HTTP header");
    headers_length = 0;
    goto clean_up;
  }  

  /* terminate the headers */
  headers[headers_length] = '\0';
  *headersp = headers;
  retcode = RECV_GOOD;

 clean_up:
  
  if(retcode != RECV_GOOD) {
    if(headers != NULL) 
      free(headers);
  }
  
  return retcode;
}




/*
  returns the response length (headers length plus content length) or < 0 on failure;
  allocs and copies the response to *responsep
  does NOT DRAIN the source of both the headers and the body
*/
rcode_t
peek_content(struct evbuffer *source, size_t headers_length, char *headers, char **responsep,
	     size_t& response_length){
  size_t content_length = 0;
  char *response = NULL; 

  response_length = 0;
  response_length += headers_length;

  if (get_content_length(headers, headers_length, content_length) != RCODE_OK)
    goto clean_up;
  

  log_debug("received content-length = %" PriSize_t "\n", content_length);
  response_length += content_length;
  response = get_response_aux(source, response_length);
   
 clean_up:  
  if(response != NULL){
    *responsep = response;
  } else {
    *responsep = NULL;
    return RCODE_ERROR;
  }
  return RCODE_OK;
}




static 
char *get_response_aux(struct evbuffer *source, size_t response_length)
{
  int success = 0;
  char* response = (char*)xmalloc(response_length + 1);

  if(response == NULL){
    log_warn("allocating response buffer failed");
    goto clean_up;
  } else {
    ev_ssize_t r = evbuffer_copyout(source, response, response_length);
    //log_warn("get_response_aux: copied %d bytes from source to response (expected %d)", (int)r, response_length);
    if (r < 0) {
      log_warn("evbuffer_copyout failed");
      goto clean_up;
    }
    if ((size_t) r < response_length) {
      log_debug("evbuffer_copyout incomplete; got %d instead of %" PriSize_t, (int)r, response_length);
      goto clean_up;
    }
    response[response_length] = '\0';
    success = 1;
  }
  
 clean_up:  
  if(!success){
    free(response);
    response = NULL;
  }
  
  return response;
}



void 
evbuffer_dump(struct evbuffer *buf, FILE *out)
{
  int nextent = evbuffer_peek(buf, SSIZE_MAX, 0, 0, 0);
  struct evbuffer_iovec v[nextent];
  int i;
  const uchar *p, *limit;

  if (evbuffer_peek(buf, -1, 0, v, nextent) != nextent)
    abort();

  for (i = 0; i < nextent; i++) {
    p = (const uchar *)v[i].iov_base;
    limit = p + v[i].iov_len;

    putc('|', out);
    while (p < limit) {
      if (*p < 0x20 || *p >= 0x7F || *p == '\\' || *p == '|')
        fprintf(out, "\\x%02x", *p);
      else
        putc(*p, out);
      p++;
    }
  }
  putc('|', out);
}





void 
buf_dump(uchar* buf, size_t len, FILE *out)
{
  size_t i = 0;
  putc('|', out);
  while (i < len) {
    if (buf[i] < 0x20 || buf[i] >= 0x7F || buf[i] == '\\' || buf[i]== '|')
      fprintf(out, "\\x%02x", buf[i]);
    else
      putc(buf[i], out);
    i++;
  }
  putc('|', out);
  putc('\n', out);
}


size_t 
clamp(size_t val, size_t lo, size_t hi)
{
  if (val < lo) return lo;
  if (val > hi) return hi;
  return val;
}




int 
lookup_peer_name_from_ip(const char* p_ip, char* p_name, int p_name_size)  
{
  int retval = 0;
  struct addrinfo* ailist = NULL;
  struct addrinfo* aip;
  struct addrinfo hint;
  int res;
  char buf[128];

  assert(p_name_size > 0);
  hint.ai_flags = AI_CANONNAME;
  hint.ai_family = PF_UNSPEC;
  hint.ai_socktype = 0;
  hint.ai_protocol = 0;
  hint.ai_addrlen = 0;
  hint.ai_canonname = NULL;
  hint.ai_addr = NULL;
  hint.ai_next = NULL;

  strncpy(buf, p_ip, 128);
  buf[127] = '\0';

  if (strchr(buf, ':') != NULL) {
    buf[strchr(buf, ':') - buf] = '\0';
  } else {
    goto clean_up;
  }

  if ((res = getaddrinfo(buf, NULL, &hint, &ailist))) {
    log_warn("getaddrinfo(%s) failed: %s", p_ip, gai_strerror(res));
    goto clean_up;
  }

  for (aip = ailist; aip != NULL; aip = aip->ai_next) {
    char buf[512];
    if (getnameinfo(aip->ai_addr, sizeof(struct sockaddr),
        buf, 512, NULL, 0, 0) == 0) {
      strncpy(p_name, buf, p_name_size);
      p_name[p_name_size-1] = '\0';
      retval = 1;
      goto clean_up;
    }
  }
 clean_up:
  if(ailist != NULL){ freeaddrinfo(ailist); }
  return retval;
}



/*
 * bool is_hex_string(char *str, size_t str_length)
 *
 * description:
 *   return true if all char in str are hexadecimal
 *   return false otherwise
 *
 */
bool 
is_hex_string(char *str, size_t str_length) 
{
  size_t i;
  char *dp = str;

  for (i = 0; i < str_length; i++) {
    if (! isxdigit(*dp) ) {
      return false;
    }
  }

  return true;
}


/* 0 on success , -1 on failure: guesses a size, then reallocs if too small -- compressed_datap receives the newly allocated buffer */
int 
compressor(char* data,  size_t datalen, char** compressed_datap, size_t *compressed_datalenp)
{
  if((data == NULL) || (datalen == 0) || (compressed_datap == NULL) || (compressed_datalenp == NULL)){
    return -1;
  } else {
    ssize_t compressed_datalen = 0;
    size_t  buffer_len = datalen < 18 ? datalen + 18 : datalen * 2;
    char *buffer = (char *)xmalloc(buffer_len);
    memset(buffer, 0, buffer_len);
    if(buffer == NULL){ return -1; }
    compressed_datalen = compress((const uint8_t *)data, datalen,  (uint8_t *)buffer, buffer_len, c_format_gzip);

    if(compressed_datalen != -1){
      *compressed_datap = buffer;
      *compressed_datalenp = compressed_datalen;
      return 0;
    } else {
      free(buffer);
      return -1;
    }
  }
}

/* 0 on success , -1 on failure: guesses a size, then reallocs if too small -- decompressed_datap receives the newly allocated buffer  */
int 
decompressor(char* data,  size_t datalen, char** decompressed_datap, size_t *decompressed_datalenp)
{
  int retval = -1;

  if((data == NULL) || (datalen == 0) || (decompressed_datap == NULL) || (decompressed_datalenp == NULL)){
    return -1;
  } 
  else {
    ssize_t decompressed_datalen = 0;
    size_t buffer_len = datalen * 8;
    char *buffer = (char *)xmalloc(buffer_len);
    int max_iterations = 0;

    if(buffer == NULL){ return retval; }

    while(max_iterations++ < 4){
      decompressed_datalen = decompress((const uint8_t *)data, datalen, (uint8_t *)buffer, buffer_len);

      if(decompressed_datalen != -2){
        break;
      } else {

        log_debug("decompressor: growing from %" PriSize_t " to %" PriSize_t, buffer_len, 2 * buffer_len);
        buffer_len = (buffer_len * 2);
        //always keep 1 full the terminating NULL
        buffer = (char *)xrealloc(buffer, buffer_len + 1);
      }
    }

    if(decompressed_datalen < 0){
      free(buffer);
      return -1;
    } else {
      *decompressed_datap = buffer;
      *decompressed_datalenp = decompressed_datalen;
      buffer[decompressed_datalen] = '\0';
      return 0;
    }
  }
}



/* just a rough estimate  */
void 
profile_data(const char* scheme, size_t headers_length, size_t body_length, size_t source_length)
{
  char buffer[2048];
  size_t in = source_length;
  size_t out = headers_length + body_length;

  snprintf(buffer, 2048, "%s: sent %" PriSize_t " in %" PriSize_t " content (i.e. %d per cent expansion)", scheme, in, out, (int)(((out - in) * 100)/in));
  log_warn("%s", buffer);
}

