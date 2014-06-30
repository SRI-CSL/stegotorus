/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

/* jsSteg: A JavaScript-based steganography module */

#include "util.h"
#include "payloads.h"
#include "jsSteg.h"
#include "compression.h"
#include "connections.h"
#include "shared.h"
#include "schemes.h"
#include "headers.h"
#include "jsutil.h"
#include "protocol.h"
#include "strncasestr.h"
#include "oshacks.h"

#include <ctype.h>

#include <event2/buffer.h>


static size_t construct_js_headers(int method, const char* path, const char* host, const char* cookie, size_t body_length, char* headers, const char* content_type, int zipped);

rcode_t construct_js_body(payloads &pl, char* data, size_t data_length, unsigned char** bodyp, size_t& body_len, unsigned int content_type, int zipped); 

rcode_t deconstruct_js_body(unsigned char *body, size_t body_len, unsigned char** datap, size_t& data_len, int zipped, int content_type);


rcode_t encode_HTTP_body (char *data, char *j_template, char *j_data, size_t dlen, size_t jtlen, size_t jdlen, int mode, size_t& enc_cnt);

rcode_t decode_HTTP_body (char *j_data, char *data_buf, size_t jdlen, size_t data_buf_size, int *fin, int mode, size_t& dec_cnt);

rcode_t encode (char *data, char *j_template, char *j_data, size_t dlen, size_t jtlen, size_t jdlen, int *fin);

rcode_t decode (char *j_data, char *data_buf, size_t jdlen, size_t data_buf_size, int *fin );



/*
 * function: encode
 *
 * description:
 *   embed hex-encoded data (data) in the input Javascript (j_template)
 *   and put the result in j_data
 *   function returns RCODE_OK on success, or returns RCODE_ERROR on failure.
 *
 * approach:
 *   replaces characters in j_template that are hexadecimal (i.e., {0-9,a-f,A-F})
 *   with those in data, and leave the non-hex char in place
 *
 * input:
 *   - data[] : hex data to hide
 *   - dlen   : size of data
 *   - j_template[] : Javascript
 *   - jlen   : size of j_template
 *   - jdlen  : size of j_data, output buffer
 *
 * output:
 *   - j_data : result of encoding data in j_template
 *   - fin    : signal the caller whether all data has been encoded and
 *              a JS_DELIMITER has been added
 *   - enc_cnt: number of data char encoded
 *
 * assumptions:
 *   - data is hex-encoded
 *
 * This function uses offset2Hex to look for usable hex char
 * in JS for encoding. See offset2Hex for what hex char are considered
 * usable. encode() also converts JS_DELIMITER that appears in the
 * the JS to JS_DELIMITER_REPLACEMENT, before all the data is encoded.
 *
 */

rcode_t
encode(char *data, char *j_template, char *j_data, size_t dlen, size_t jtlen,
       size_t jdlen, int *fin, size_t& enc_cnt)
{
  enc_cnt = 0;  /* num of data encoded in j_data */
  char *dp, *jtp, *jdp; /* current pointers for data, j_template, and j_data */
  int i,j;

  dp = data;
  jtp = j_template;
  jdp = j_data;

  /*
   *  Because this function embeds data into j_template by rewriting selected char
   *  of the latter, the output (j_data) has the same length as that of j_template.
   *  Thus, we just need to ensure that the output buffer length (jdlen) is at
   *  least as large as that of j_template (jtlen)  
   */

  if (jdlen < jtlen) {
    log_warn("ERROR 1: encode: output buf too small");
    goto err;
  }

  if (! is_hex_string(dp, dlen) ) {
    log_warn("ERROR 2: encode: data not hex-encoded");
    goto err;
  }

  i = offset2Hex(jtp, (j_template+jtlen)-jtp, 0);

  while (enc_cnt < dlen && i != -1) {
    // copy next i char from jtp to jdp,
    // except that if *jtp==JS_DELIMITER, copy
    // JS_DELIMITER_REPLACEMENT to jdp instead
    j = 0;
    while (j < i) {
      if (*jtp == JS_DELIMITER) {
        *jdp = JS_DELIMITER_REPLACEMENT;
      } else {
        *jdp = *jtp;
      }
      jtp = jtp + 1;
      jdp = jdp + 1;
      j++;
    }

    *jdp = *dp;
    enc_cnt++;
    dp = dp + 1;
    jtp = jtp + 1;
    jdp = jdp + 1;

    i = offset2Hex(jtp, (j_template+jtlen)-jtp, 1);
  }


  // copy the rest of j_template to jdata
  // if we've encoded all data, replace the first
  // char in j_template by JS_DELIMITER, if needed,
  // to signal the end of data encoding
  *fin = 0;

  if (enc_cnt == dlen) {
    // replace the next alnum char in j_template by JS_DELIMITER
    i = offset2Alnum_(jtp, (j_template+jtlen)-jtp);

    if (i == -1) {

      if (memncpy (jdp, (j_data+jdlen)-jdp, jtp, (j_template+jtlen)-jtp) != RCODE_OK) {
        log_warn("ERROR 4: encode");
        goto err;
      }
      jdp += (j_template+jtlen)-jtp;
      jtp = j_template+jtlen;
      log_debug("cannot find an alnum char to put JS_DELIMTER");

    } else {

      if (i > 0) {

         if (memncpy (jdp, (j_data+jdlen)-jdp, jtp, i) != RCODE_OK) {
           log_warn("ERROR 5: encode");
           goto err;
         }
         jdp += i;
         jtp += i;
      }
      *jdp = JS_DELIMITER;
      jdp = jdp+1;
      jtp = jtp+1;
      *fin = 1;
    }
  }


  while (jtp < (j_template+jtlen)) {
    if (*jtp == JS_DELIMITER) {
      if (enc_cnt < dlen) {
        *jdp = JS_DELIMITER_REPLACEMENT;
      } else {
        *jdp = *jtp;
      }
    } else {
      *jdp = *jtp;
    }
    jdp = jdp+1;
    jtp = jtp+1;
  }

  return RCODE_OK;

 err:
  log_warn("encode failed");
  return RCODE_ERROR;
  
}




rcode_t 
encode_HTTP_body(char *data, char *j_template, char *j_data, size_t dlen, size_t jtlen,
		 size_t jdlen, int mode, size_t& enc_cnt)
{
  char *dp, *jtp, *jdp; // current pointers for data, j_template, and j_data
  enc_cnt = 0;  // num of data encoded in j_data
  char *js_start, *js_end;
  int skip;
  int script_len;
  int fin = 0;
  size_t dlen2 = dlen;
  size_t enc_inc;

  dp = data;
  jtp = j_template;
  jdp = j_data;

  if (mode != CONTENT_JAVASCRIPT && mode != CONTENT_HTML_JAVASCRIPT) {
    log_warn("ERROR 1: encode_HTTP_body: Unknown mode (%d) for encode_HTTP_body()", mode);
    goto err;
  }

  if (mode == CONTENT_JAVASCRIPT) {
    // assumption: the javascript pertaining to j_template has enough capacity
    // to encode j_data. thus, we only invoke encode() once here.
    if (encode(dp, jtp, jdp, dlen, jtlen, jdlen, &fin, enc_cnt) != RCODE_OK)
      goto err;

    // ensure that all dlen char from data have been encoded in j_data
    if (enc_cnt != dlen || fin == 0) {
      log_warn("ERROR 2: encode_HTTP_body: problem encoding all data to the JS");
      goto err;
    }

  }

  if (mode == CONTENT_HTML_JAVASCRIPT) {
    while ((enc_cnt < dlen2) || (fin == 0)) {
      js_start = strnstr(jtp, JS_SCRIPT_START, jtlen);

      if (js_start == NULL) {
        log_warn("lack of usable JS; can't find JS_SCRIPT_START");
        goto err;
      }
      skip = strlen(JS_SCRIPT_START)+js_start-jtp;

      if (memncpy (jdp, (j_data+jdlen)-jdp, jtp, skip) != RCODE_OK) {
        log_warn("ERROR 3: encode_HTTP_body: invalid data size");
        goto err;
      }   

      jtp = jtp+skip; jdp = jdp+skip;
      js_end = strnstr(jtp, JS_SCRIPT_END, jtlen-(jtp-j_template));

      if (js_end == NULL) {
        log_warn("lack of usable JS; can't find JS_SCRIPT_END");
        goto err;
      }

      // the JS for encoding data is between js_start and js_end
      script_len = js_end - jtp;
      if (encode(dp, jtp, jdp, dlen, script_len, jdlen, &fin, enc_inc) != RCODE_OK)
        goto err;

      // update enc_cnt, dp, and dlen based on enc_inc
      if (enc_inc > 0) {
        enc_cnt = enc_cnt+enc_inc; 
        dp = dp+enc_inc; 
        dlen = dlen-enc_inc;
      }
      // update jtp and jdp
      skip = js_end-jtp;
      jtp = jtp+skip; 
      jdp = jdp+skip;
      skip = strlen(JS_SCRIPT_END);

      if (memncpy (jdp, (j_data+jdlen)-jdp, jtp, skip) != RCODE_OK) {
        //(size_t) cast is for the mac cross compile build in gitian.
        log_warn("ERROR 4: encode_HTTP_body: invalid data size dst len:%" PriSize_t "; src len %d", (size_t)((j_data+jdlen)-jdp), skip);
        goto err;
      }   

      jtp = jtp+skip; 
      jdp = jdp+skip;
    }

    // copy the rest of j_template to jdp
    skip = j_template+jtlen-jtp;

    if (memncpy (jdp, (j_data+jdlen)-jdp, jtp, skip) != RCODE_OK) {
      log_warn("ERROR 5: encode_HTTP_body: invalid data size");
      goto err;
    }   

  }
  return RCODE_OK;

 err:
  log_warn("encode_HTTP_body failed");
  return RCODE_ERROR;
}




/* 
 * function: decode
 *
 * description:
 *   extract hex char from Javascript embedded with data (j_data)
 *   and put the result in data_buf
 *   function returns RCODE_OK on success, or RCODE_ERROR on failure
 *
 * input:
 *   - j_data[]: Javascript embedded with hex-encoded data
 *   - jdlen  : size of j_data
 *   - dlen   : size of data to recover
 *   - data_buf_size : size of output data buffer (data_buf)
 *
 * output:
 *   - data_buf[] : output buffer for recovered data
 *   - dec_cnt: number of hex char extracted from j_data to data_buf
 *
 * assumptions:
 *   - data is hex-encoded
 *
 * This function uses offset2Hex to look for
 * applicable hex char in JS for decoding. Also, the decoding process
 * stops when JS_DELIMITER is encountered.
 */

rcode_t 
decode (char *j_data, char *data_buf, size_t jdlen, size_t data_buf_size, int *fin, size_t& dec_cnt)
{
  dec_cnt = 0;  /* num of data decoded */
  char *dp, *jdp; /* current pointers for data_buf and j_data */
  int i,j;
  int cjdlen = jdlen;

  *fin = 0;
  dp = data_buf; 
  jdp = j_data;

  i = offset2Hex(jdp, cjdlen, 0);

  while (i != -1) {
    // return if JS_DELIMITER exists between jdp and jdp+i

    for (j=0; j<i; j++) {

      if (*jdp == JS_DELIMITER) {
        *fin = 1;
        goto done;
      }
      jdp = jdp+1;
      cjdlen--;
    }

    // copy hex data from jdp to dp
    if (data_buf_size <= 0) {
      goto done;
    }
    *dp = *jdp;
    jdp = jdp+1; 
    cjdlen--;
    dp = dp+1; 
    data_buf_size--;
    dec_cnt++;

    // find the next hex char
    i = offset2Hex(jdp, cjdlen, 1);
  }

  // look for JS_DELIMITER between jdp to j_data+jdlen
  while (jdp < j_data+jdlen) {

    if (*jdp == JS_DELIMITER) {
      *fin = 1;
      break;
    }
    jdp = jdp+1;
  }

 done:
  return RCODE_OK;
}




rcode_t 
decode_HTTP_body (char *j_data, char *data_buf, size_t jdlen, size_t data_buf_size, int *fin, int mode, size_t& dec_cnt)
{
  char *js_start, *js_end;
  char *dp, *jdp; // current pointers for data and j_data
  int script_len;
  dec_cnt = 0;
  size_t dec_inc;
  int dlen = data_buf_size;
  dp = data_buf; jdp = j_data;

  if (mode != CONTENT_JAVASCRIPT && mode != CONTENT_HTML_JAVASCRIPT) {
    log_warn("Unknown mode (%d) for decode_HTTP_body()", mode);
    goto err;
  }

  if (mode == CONTENT_JAVASCRIPT) {
    if (decode(j_data, data_buf, jdlen, data_buf_size, fin, dec_cnt) != RCODE_OK) {
      goto err;
    }

    if (*fin == 0) {
      log_warn("Unable to find JS_DELIMITER");
      goto err;
    }
  }

  if (mode == CONTENT_HTML_JAVASCRIPT) {
    *fin = 0;
    while (*fin == 0) {
      js_start = strnstr(jdp, JS_SCRIPT_START, jdlen);

      if (js_start == NULL) {
        log_warn("Can't find JS_SCRIPT_START for decoding data inside script type JS");
        goto err;
      }
      jdp = js_start+strlen(JS_SCRIPT_START);
      js_end = strnstr(jdp, JS_SCRIPT_END, jdlen-(jdp-j_data));

      if (js_end == NULL) {
        log_warn("Can't find JS_SCRIPT_END for decoding data inside script type JS");
        goto err;
      }

      // the JS for decoding data is between js_start and js_end
      script_len = js_end - jdp;

      if (decode(jdp, dp, script_len, dlen, fin, dec_inc) != RCODE_OK) {
        goto err;
      }

      if (dec_inc > 0) {
        dec_cnt = dec_cnt+dec_inc;
        dlen=dlen-dec_inc;
        dp=dp+dec_inc;
      }
      jdp = js_end+strlen(JS_SCRIPT_END);
    } // while (*fin==0)
  }

  return RCODE_OK;

 err:
  log_warn("decode_HTTP_body failed");
  return RCODE_ERROR;

}



transmit_t
http_server_JS_transmit (http_steg_t * s, struct evbuffer *source, unsigned int content_type) {
  // char *secret = s->config->shared_secret;
  payloads pl = s->config->pl;
  transmit_t retval = NOT_TRANSMITTED;
  conn_t *conn = s->conn;
  char* headers = NULL;
  char* data = NULL;
  unsigned char *body = NULL;

  if((source == NULL) || (conn == NULL)){
    log_warn("bad args");
    goto clean_up;
  } 
  else {
    size_t source_length = evbuffer_get_length(source);
    size_t body_length = 0, headers_length = 0, data_length = 0;
    struct evbuffer *dest = conn->outbound();

    headers = (char *)xzalloc(MAX_HEADERS_SIZE);

    if(headers == NULL){
      log_warn("header allocation failed.");
      goto clean_up;
    }

    log_debug("source_length = %d", (int) source_length);

    if (source2hex(source, source_length, &data, data_length) != RCODE_OK) {
      log_warn("extracting raw to send failed");
      goto clean_up;
    }

    if (construct_js_body(pl, data, data_length, &body, body_length, content_type, s->accepts_gzip) != RCODE_OK) {
      log_warn("construct_js_body failed.");
      goto clean_up;
    }

    if (content_type == HTTP_CONTENT_JAVASCRIPT) {
      headers_length = construct_js_headers(HTTP_GET, NULL, NULL, NULL, body_length, headers, JAVASCRIPT_CONTENT_TYPE, s->accepts_gzip);
    } else if (content_type == HTTP_CONTENT_HTML) {
      headers_length = construct_js_headers(HTTP_GET, NULL, NULL, NULL, body_length, headers, HTML_JAVASCRIPT_CONTENT_TYPE, s->accepts_gzip);
    } else {
      log_warn("unsupported content_type (%d)", content_type);
      goto clean_up;
    }

    if(headers_length == 0){
      log_warn("construct_js_headers failed.");
      goto clean_up;
    }

    log_debug("http_server_JS_transmit: data_length = %d  body_length = %d", (int)data_length, (int)body_length);

    if (evbuffer_add(dest, headers, headers_length)  == -1) {
      log_warn("evbuffer_add() fails for headers");
      goto clean_up;
    }

    if (evbuffer_add(dest, body, body_length)  == -1) {
      log_warn("evbuffer_add() fails for body");
      goto clean_up;
    }

    evbuffer_drain(source, source_length);

    if (SCHEMES_PROFILING) {
      profile_data("JS", headers_length, body_length, source_length);
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
http_client_JS_receive (http_steg_t * s, struct evbuffer *dest, char* headers, size_t headers_length, char* response, size_t response_length) {
  // char *secret = s->config->shared_secret;
  recv_t retval = RECV_BAD;
  size_t body_length = 0;
  size_t data_length = 0;
  unsigned char *data = NULL, *body = NULL;
  int content_type;

  body = (unsigned char*)&response[headers_length];
  body_length = response_length - headers_length;

  content_type = find_content_type (headers, headers_length);

  if (content_type != HTTP_CONTENT_JAVASCRIPT && content_type != HTTP_CONTENT_HTML) {
    log_warn("ERROR: Invalid content type (%d)", content_type);
    goto clean_up;
  }

  if (deconstruct_js_body(body, body_length, &data, data_length, s->is_gzipped, content_type) != RCODE_OK)
    goto clean_up;

  retval = hex2dest(dest, data_length, (char *)data);

  clean_up:
  if(data != NULL){ free(data); }
  return retval;
}




size_t
construct_js_headers(int method, const char* path, const char* host, const char* cookie, size_t body_length, char* headers, const char* content_type, int zipped) 
{
  /* use them or .. */
  log_debug("path = %s; host = %s", path, host);

  size_t headers_length = MAX_HEADERS_SIZE;
  if (method == HTTP_GET) {
    if (gen_response_header(content_type, cookie, zipped, body_length, headers, headers_length, headers_length) != RCODE_OK)
      goto err;
  } else {
    log_warn("Bad method %d to construct_js_headers (HTTP_GET = %d, HTTP_POST = %d)", method, HTTP_GET, HTTP_POST);
  }
 
  return headers_length;
  
 err:
  return 0;
}



rcode_t
construct_js_body(payloads &pl, char* data, size_t data_length, unsigned char** bodyp, size_t& body_len, unsigned int content_type, int zipped) 
{
  char *js_template = NULL, *http_head_end;
  size_t js_template_size = 0;
  int http_head_len, outbuf2len, mode, body_length;
  char *outbuf = NULL, *outbuf2 = NULL;
  size_t enc_cnt;

  if (bodyp != NULL){
    if (get_payload(pl, content_type, data_length/2, js_template, js_template_size) == RCODE_OK) {
      log_debug("Found HTTP JS template with size %" PriSize_t, js_template_size);
    } else {
      log_warn("Unable to find HTTP JS template");
      goto err;
    }

    http_head_end = strnstr(js_template, "\r\n\r\n", js_template_size);

    if (http_head_end == NULL) {
      log_warn("Unable to find the end of HTTP header");
      goto err;
    }

    http_head_len = http_head_end+4-js_template;
    body_length = js_template_size - http_head_len;
    outbuf = (char *) xzalloc(body_length);

    if (outbuf == NULL) {
      log_warn("buffer allocation failed");
      goto err;
    }

    mode = has_eligible_HTTP_content (js_template, js_template_size, HTTP_CONTENT_JAVASCRIPT);

    if (encode_HTTP_body(data, http_head_end+4, outbuf, data_length, body_length, body_length, mode, enc_cnt) != RCODE_OK)
      goto err;

    if (enc_cnt < data_length) {
      log_warn("incomplete data encoding");
      goto err;
    }

    if (zipped) {
      char* zbody = NULL;
      size_t zbody_len = 0;
      int cval = compressor(outbuf, body_length, &zbody, &zbody_len);

      if (cval == 0) {
        outbuf2 = zbody;
        outbuf2len = zbody_len;
      } else {
        log_warn("construct_js_body: compression (of %d bytes) went awry: %d", body_length, cval);
        goto err;
      }
      free(outbuf);
      outbuf = NULL;
    } else {
      outbuf2 = outbuf;
      outbuf2len = body_length;
    }

    *bodyp = (unsigned char *) outbuf2;
    body_len = outbuf2len;
    return RCODE_OK;
  }

 err:
  if (outbuf != NULL) free(outbuf);
  log_warn ("construct_js_body failed");
  return RCODE_ERROR;

}



rcode_t
deconstruct_js_body(unsigned char *body, size_t body_len, unsigned char** datap, size_t& data_len, int zipped, int content_type) 
{

  char *body2, *outbuf = NULL;
  size_t body_len2;
  int fin;

  if (datap != NULL) {
    outbuf = (char *) xzalloc(HTTP_MSG_BUF_SIZE);
    if (outbuf == NULL) {
      log_warn("buffer allocation failed");
      goto err;
    }
  
    if(zipped){
      char *decompressed_body = NULL;
      size_t decompressed_bodylen = 0;
  
      int dval = decompressor((char *)body, body_len, &decompressed_body, &decompressed_bodylen);
      if(dval == 0){
        body2 = decompressed_body;
        body_len2 = decompressed_bodylen;
        free(decompressed_body);
        goto err;
      } else {
        log_warn("deconstruct_js_body: decompression went awry");
        goto err;
      }
    } else {
      body2 = (char *)body;
      body_len2 = body_len;
    }
  
    if (content_type == HTTP_CONTENT_JAVASCRIPT) {

       if (decode_HTTP_body(body2, outbuf, body_len2, HTTP_MSG_BUF_SIZE, &fin, CONTENT_JAVASCRIPT, data_len) != RCODE_OK)
         goto err;

    } else {
       if (decode_HTTP_body(body2, outbuf, body_len2, HTTP_MSG_BUF_SIZE, &fin, CONTENT_HTML_JAVASCRIPT, data_len) != RCODE_OK)
         goto err;
    }

    outbuf[data_len] = 0;
    *datap = (unsigned char *)outbuf;
    return RCODE_OK;
  }

 err:
  if (outbuf != NULL) free(outbuf);
  log_warn("deconstruct_js_body failed");
  return RCODE_ERROR;
}

