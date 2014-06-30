/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "b64cookies.h"

#include "oshacks.h"

rcode_t
unwrap_b64_cookies(char *outbuf, size_t outbuflen, const char *inbuf, size_t inlen, size_t& bytes_written)
{
  size_t i;

  for (i = 0, bytes_written = 0; i < inlen; i++) {
    char c = inbuf[i];

    if (c != ' ' && c != ';' && c != '=') {
      if (bytes_written >= outbuflen)
	goto err;
      outbuf[bytes_written++] = c;
    }
  }

  return RCODE_OK;

 err:
  log_warn("unwrap b64 cookies failed");
  return RCODE_ERROR;
}



static rcode_t
gen_one_cookie(char *&outbuf, size_t outbuflen, const char *&inbuf, size_t inlen, size_t& bytes_processed)
{
  size_t adv_in = 0;
  size_t adv_out = 0;
  size_t namelen, cookielen;
  
  if (inlen < 5) {

    if (memncpy(outbuf, outbuflen, inbuf, inlen) != RCODE_OK) {
      goto err;
    }

    outbuf += inlen;
    inbuf += inlen;
    bytes_processed = inlen;
    return RCODE_OK;
  }

  if (inlen < 10) {
    namelen = rand() % 5 + 1;
  } 
  else {
    namelen = rand() % 10 + 1;
  }

  cookielen = rand() % (inlen * 2 / 3);
  if (cookielen > inlen - namelen)
    cookielen = inlen - namelen;

  if (memncpy(outbuf, outbuflen, inbuf, namelen) != RCODE_OK) {
    goto err;
  }

  adv_in += namelen;
  adv_out += namelen;
  outbuf[adv_out++] = '=';

  if (memncpy(outbuf + adv_out, outbuflen - adv_out, inbuf + adv_in, cookielen) != RCODE_OK) {
    log_warn("outbuflen = %" PriSize_t ", outbuflen - adv_out = %" PriSize_t ", cookielen = %" PriSize_t, outbuflen, outbuflen - adv_out, cookielen);
    goto err;
  }

  adv_in += cookielen;
  adv_out += cookielen;
  outbuf += adv_out;
  inbuf += adv_in;
  bytes_processed = adv_in;
  return RCODE_OK;

 err:
  log_warn("gen_one_cookie failed\n");
  return RCODE_ERROR;
}



rcode_t
gen_b64_cookies(char *outbuf, size_t outbuflen, const char *inbuf, size_t inlen, size_t& bytes_written)
{
  char *outp = outbuf;
  const char *inp = inbuf;
  size_t sofar = 0, processed = 0, remain = 0;
  
  
  while (sofar < inlen) {
    if (gen_one_cookie(outp, outbuflen - (outp - outbuf), inp, inlen - sofar, processed) != RCODE_OK)
      goto err;
    
    sofar = sofar + processed;
    remain = inlen - sofar;
    
    if (remain < 5 && remain > 0) {
      if (memncpy(outp, outbuflen - (outp - outbuf), inp, remain) != RCODE_OK)
	goto err;
      outp += remain;
      inp += remain;
      break;
    }

    if (remain > 0)
      *outp++ = ';';
  }

  bytes_written = outp - outbuf;
  return RCODE_OK;

 err:
  return RCODE_ERROR;
}
