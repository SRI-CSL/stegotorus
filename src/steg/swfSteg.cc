/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */


#include <event2/buffer.h>
#include "util.h"
#include "swfSteg.h"
#include "compression.h"
#include "connections.h"
#include "payloads.h"
#include "base64.h"
#include "headers.h"
#include "protocol.h"
#include "strncasestr.h"
#include "oshacks.h"






rcode_t
swf_wrap(payloads& pl, char* inbuf, size_t in_len, char*& outbuf, size_t out_sz,
	 size_t& bytes_written) {

  char* tmp_buf = NULL, *tmp_buf2 = NULL, *resp = NULL;
  size_t hdr_len;
  size_t tmp_buf_len = 0, b64_len = 0, resp_len = 0;
  size_t out_data_len;
  ssize_t out_swf_len = 0;
  char hdr[512];
  char b64_buf [in_len * 2];

  bytes_written = 0;

  // '+' -> '-', '/' -> '_', '=' -> '.' per
  // RFC4648 "Base 64 encoding with URL and filename safe alphabet"
  base64::encoder E(false, '-', '_', '.');
  b64_len  = E.encode(inbuf, in_len, b64_buf);
  b64_len += E.encode_end(b64_buf + b64_len);
  b64_buf[b64_len] = 0;

  for (int j=2; j > 0; j--) {
    int end = b64_len-j;
    if (b64_buf[end] == '.') {
      b64_buf[end] = 0;
      b64_len = end;
      break;
    }
  }
  
  if (get_payload(pl, HTTP_CONTENT_SWF, -1, resp, resp_len) != RCODE_OK) {
    log_warn("swfsteg: no suitable payload found");
    goto err;
  }

   tmp_buf_len = resp_len + 512 + 8*b64_len;
   tmp_buf = (char *)xmalloc(tmp_buf_len);
   tmp_buf2 = (char *)xmalloc(tmp_buf_len);

   if((tmp_buf == NULL) || (tmp_buf2 == NULL)){
     goto err;
   }

   if (parse_swf((unsigned char*) resp, resp_len, (unsigned char*) tmp_buf, tmp_buf_len, 
		 (unsigned char*) b64_buf, b64_len, out_data_len) != RCODE_OK)
     goto err;

   out_swf_len = compress((const uint8_t *)tmp_buf, out_data_len, (uint8_t *)tmp_buf2+8, tmp_buf_len - 8, c_format_zlib);

   if (out_swf_len < 0)
     goto err;

   if (gen_response_header((char*) "application/x-shockwave-flash", NULL, 0, out_swf_len + 8, hdr, sizeof(hdr), hdr_len) != RCODE_OK)
     goto err;
   
   if (memncpy(tmp_buf2, tmp_buf_len, "CWS", 3) != RCODE_OK)
     goto err;

   tmp_buf2[3] = 8;
   ((uint32_t *) (tmp_buf2))[1] = out_swf_len;
   
   /* realloc the outbuf if necessary. */
   if (out_sz < hdr_len + out_swf_len + 8) {
     log_warn("swfsteg: outbuf too small");
     free(outbuf);
     outbuf = (char*) xmalloc(hdr_len + out_swf_len + 8);
     out_sz = hdr_len + out_swf_len + 8;
   }

   if (memncpy(outbuf, out_sz, hdr, hdr_len) != RCODE_OK)
     goto err;

   if (memncpy(outbuf + hdr_len, out_sz - hdr_len, tmp_buf2, out_swf_len + 8) != RCODE_OK)
     goto err;
      
   if (tmp_buf != NULL) 
     free(tmp_buf);
     

   if (tmp_buf2 != NULL)
     free(tmp_buf2);

   bytes_written =  out_swf_len + 8 + hdr_len;
   return RCODE_OK;

 err:
   if (tmp_buf != NULL)
     free (tmp_buf);
   if (tmp_buf2 != NULL)
     free (tmp_buf2);

   log_warn("swf_wrap failed");
   return RCODE_ERROR;
}



 
rcode_t
swf_unwrap(char* inbuf, size_t in_len, char* outbuf, size_t out_sz, size_t& bytes_written)
{
  ssize_t inf_len;
  size_t tmp_len = in_len * 16 + 512;
  char* tmp_buf = (char *)xmalloc(tmp_len);
  char* tmp_buf2 = (char *)xmalloc(tmp_len);
  size_t rdatalen;
  rcode_t retval = RCODE_ERROR;
  base64::decoder D('-', '_');

  bytes_written = 0;

  if((tmp_buf == NULL) || (tmp_buf2 == NULL)){
    log_warn("xmalloc failed: tmp_len = %u", (unsigned int)tmp_len);
    goto clean_up;
  }
  
  for (;;) {
    inf_len = decompress((const uint8_t *)inbuf + 8, in_len - 8,
                         (uint8_t *)tmp_buf, tmp_len);
    if (inf_len != -2)
      break;
    tmp_len *= 2;
    tmp_buf = (char *)xrealloc(tmp_buf, tmp_len);

    if(tmp_buf == NULL) {
      log_warn("xrealloc failed: tmp_len = %u", (unsigned int)tmp_len);
      goto clean_up;
    }
  }

  if (inf_len < 0 ) {
    log_warn("inf_len = %" PriSSize_t, (ssize_t)inf_len);
    goto clean_up;
  }

  if (recover_data((unsigned char*) tmp_buf, inf_len, (unsigned char*) tmp_buf2, tmp_len, rdatalen) != RCODE_OK)
    goto clean_up;

  while (rdatalen % 4 != 0) {
    tmp_buf2[rdatalen] = '.';
    rdatalen++;
  }

  tmp_buf2[rdatalen] = 0;

  if (out_sz < rdatalen) {
    log_warn("decode, outbuf maybe too small = %" PriSize_t " %" PriSize_t, out_sz, rdatalen);
    goto clean_up;
  }
    
  bytes_written  = D.decode((char*) tmp_buf2, rdatalen, outbuf);

  if ( bytes_written > 0)
    retval = RCODE_OK;

 clean_up:
  if (tmp_buf != NULL) free(tmp_buf);
  if (tmp_buf2 != NULL) free(tmp_buf2);
  return retval;
}




transmit_t
http_server_SWF_transmit(payloads& pl, struct evbuffer *source, conn_t *conn)
{
  transmit_t retval = NOT_TRANSMITTED;
  struct evbuffer *dest = conn->outbound();
  char *inbuf = NULL, *outbuf = NULL;
  size_t outlen = 0, bytes_removed = 0, sbuflen = 0;
  int rval;

  //pad
  char padbuf[2];
  size_t buflen = evbuffer_get_length(source);

  padbuf[0] = randomg() % 255;
  padbuf[1] = randomg() % 255;

  if (buflen % 3 == 2) 
    evbuffer_add(source, padbuf, 1);
  else if (buflen % 3 == 1)
    evbuffer_add(source, padbuf, 2);

  //get the size after padding
  sbuflen = evbuffer_get_length(source);
  
  inbuf = (char *)xmalloc(sbuflen);

  if (inbuf == NULL)
    goto clean_up;

  rval = evbuffer_remove(source, inbuf, sbuflen);

  if (rval == -1) {
    log_debug("evbuffer_remove failed in http_server_SWF_transmit");
    goto clean_up;
  }

  bytes_removed = (size_t) rval;

  if(bytes_removed !=  sbuflen){
    log_warn("evbuffer_remove got %" PriSize_t " bytes, expected %" PriSize_t, bytes_removed, sbuflen);
    goto clean_up;
  }
  
  // allocate 1 MB... if its insufficient swf_wrap will reallocate
  outbuf = (char *)xmalloc(1000000);

  if(outbuf == NULL){
    log_warn("xmalloc failed");
    goto clean_up;
  }

  log_debug("wrapping swf len %d", (int) sbuflen);

  if (swf_wrap(pl, inbuf, sbuflen, outbuf, (uint32_t) 1000000, outlen) != RCODE_OK)
    goto clean_up;

  if (evbuffer_add(dest, outbuf, outlen)) {
    log_warn("evbuffer_add() fails for");
    goto clean_up;
  }
  retval = TRANSMIT_GOOD;

 clean_up:
  if (retval != TRANSMIT_GOOD)
    log_warn("SWF transmit failed");

  if(inbuf != NULL){ free(inbuf); }
  if(outbuf != NULL){ free(outbuf); }
  return retval;
}




recv_t
http_client_SWF_receive (http_steg_t *, struct evbuffer *dest, char* headers, size_t headers_length, 
			 char* response, size_t response_length)
{

  char *outbuf = NULL, *body = NULL;
  size_t outbuf_len = 0, content_len = 0, bytes_unwrapped = 0;

  if (get_content_length(headers, headers_length, content_len) != RCODE_OK) {
    log_warn("CLIENT unable to find content length");
    return RECV_BAD;
  }

  log_debug("CLIENT received Content-Length = %" PriSize_t, content_len);

  if (headers_length + content_len > response_length)
    return RECV_INCOMPLETE;

  body = response + headers_length;

  outbuf_len = HTTP_MSG_BUF_SIZE;
  outbuf = (char *)xmalloc(outbuf_len);

  if (!outbuf) {
    log_warn("No memory for output buffer");
    return RECV_BAD;
  }

  if (swf_unwrap(body, content_len, outbuf, outbuf_len, bytes_unwrapped) != RCODE_OK) {
    log_warn("CLIENT ERROR: swf_unwrap failed");
    goto err;
  }

  if (evbuffer_add(dest, outbuf, bytes_unwrapped)) {
    log_warn("CLIENT ERROR: evbuffer_add to dest fails");
    goto err;
  }

  if (outbuf != NULL) free(outbuf);
  return RECV_GOOD;

 err:
  if (outbuf != NULL) free(outbuf);
  return RECV_BAD;
}
