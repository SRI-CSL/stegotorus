/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

/* pdfSteg: A PDF-based steganography module */

#include "util.h"
#include "payloads.h"
#include "pdfSteg.h"
#include "connections.h"
#include "shared.h"
#include "schemes.h"
#include "headers.h"
#include "protocol.h"
#include "compression.h"
#include "strncasestr.h"
#include "oshacks.h"

#include "pdfs.h"

#include <event2/buffer.h>

static size_t construct_pdf_headers(int method, const char* path, const char* host, const char* cookie, size_t body_length, char* headers);

rcode_t construct_pdf_body(payloads &pl, unsigned char* data, size_t data_length, unsigned char**bodyp, size_t& body_len);
rcode_t construct_pdf_post_body(payloads &pl, unsigned char* data, size_t data_length, unsigned char**bodyp, size_t& body_len);
rcode_t deconstruct_pdf_body(unsigned char *body, size_t body_length, unsigned char** datap, size_t& data_len);



/*
 * str_in_binary_rewind looks for char array pattern of length pattern_len
 * in a char array blob of length blob_len in the *reverse* direction
 *
 * return a pointer for the first occurrence of pattern in blob,
 * starting from the end of blob, if found; otherwise, return NULL
 *
 */
char *
str_in_binary_rewind (const char *pattern, size_t pattern_len, const char *blob, size_t blob_len)
{
  int found = 0;
  char *cp;

  if (pattern_len < 1 || blob_len < 1) 
    return NULL;

  cp = (char *) blob + blob_len - 1;

  while ((size_t) (cp - blob + 1) >= pattern_len ) {
    if (memcmp(cp-(pattern_len-1), pattern, pattern_len) == 0) {
      found = 1;
      break;
    }
    cp--;
  }

  if (found) 
    return (cp-(pattern_len-1));
  return NULL;
}







rcode_t 
fix_xref_table(const char*& template_p, long stream_start_offset, const char* template_end,
	       char*& op, char* outbuf, size_t outbufsize, size_t diff_len) 
{
  long offset = 0, xref_offset = 0, xref_offset_orig = 0, gen_no = 0;
  int nbytes = 0, nfields = 0;
  unsigned int line_count = 0;
  size_t size = 0;
  const char* xref_p, *end_of_line;
  char* startxrefp = NULL;
  char pad[512], offset_buf[11], gen_no_buf[6], flag;

  xref_p = template_p;
  end_of_line = strpbrk (xref_p, "\r\n");

  if (end_of_line == NULL) {
    log_warn("Fail to read the xref table");
    goto err;
  }

  while ((end_of_line < template_end) &&  (memcmp(xref_p, "trailer", 7) != 0)) {
    if (memncpy(pad, 512, (void *)xref_p, end_of_line-xref_p) != RCODE_OK) {
      log_debug("fix_xref_table (1): memncpy failed");
      goto err;
    }

    pad[end_of_line-xref_p] = '\0';
    xref_p = end_of_line + 1;

    // handling the case of having a 2-char end of line
    if (end_of_line[0] == '\r' && end_of_line[1] == '\n') {
      xref_p++;
    } 
 
    if (line_count < 2) {
      size = xref_p-template_p;
      if (memncpy (op, (outbuf+outbufsize)-op, (void *)template_p, size) != RCODE_OK) {
        log_warn("fix_xref_table (2): memncpy failed");
        goto err;
      }

      template_p = xref_p; 
      op += size;
    } 
    else {
      nfields = sscanf(pad, "%10s %5s %c", offset_buf, gen_no_buf, &flag);

      // offset, generation number, flag
      if (nfields != 3) {
        log_warn("Fail to read the xref table: missing fields (%d)", nfields);
        if (nfields > 0) log_warn("Field 1 =%s", offset_buf);
        if (nfields > 1) log_warn("Field 2 =%s", gen_no_buf);
        if (nfields > 2) log_warn("Field 3 =%c", flag);
	goto err;
      }

      offset = strtol(offset_buf, (char **)NULL, 10);

      if (offset <= stream_start_offset) {
        size = xref_p-template_p;

        if (memncpy(op, (outbuf+outbufsize)-op, (void *)template_p, size) != RCODE_OK) {
          log_warn("fix_xref_table (3): memncpy failed");
          goto err;
        }

        template_p = xref_p; 
	op += size;
      } 
      else {
	gen_no = strtol(gen_no_buf, (char **)NULL, 10);
        offset = offset + diff_len;
        // note: each xref entry has exactly 20 bytes (including eol)
        // thus, we add a space char after the flag 
        nbytes = snprintf(op, 21, "%010ld %05ld %c \n", offset, gen_no, flag); 

        if (nbytes < 0) {
          log_warn("Fail to convert the xref table: snprintf fails (%d)", nbytes);
          goto err;
        }

        template_p = xref_p; 
	op += nbytes;
      }
    }

    line_count++;
    end_of_line = strpbrk (xref_p, "\r\n");
  }


  // copy the text between trailer to xstartref (inclusively) to the output buffer
  if (memcmp(template_p, "trailer", 7) != 0) {
    log_warn("trailer tag expected");
    goto err;
  }

  startxrefp = str_in_binary("startxref", 9, template_p, template_end-template_p);
  if (startxrefp == NULL) {
    log_warn("Cannot find startxrefp in pdf");
    goto err;
  }

  size = startxrefp - template_p + 10;

  if (startxrefp[9] == '\r' &&  startxrefp[10] == '\n') 
    size++;

  if (memncpy(op, (outbuf+outbufsize)-op, (void *)template_p, size) != RCODE_OK) {
    log_warn("fix_xref_table (4): memncpy failed");
    goto err;
  }

  template_p += size; 
  op += size;
  end_of_line = strpbrk (template_p, "\r\n");

  if (end_of_line == NULL) {
    log_warn("Failed to read the xref table: skipping over xstartref value");
    goto err;
  }

  // compute the new xstartref val
  if (memncpy(pad, 512, (void *)template_p, end_of_line-template_p) != RCODE_OK) {
    log_warn("fix_xref_table (5): memncpy failed");
    goto err;
  }

  pad[end_of_line-template_p] = '\0';
  nfields = sscanf(pad, "%10s", offset_buf);

  if (nfields != 1) {
    log_warn("Fail to read xstartref value: missing fields (%d)", nfields);
    goto err;
  }
  xref_offset_orig = strtol(offset_buf, (char **)NULL, 10);

  if (xref_offset_orig <= stream_start_offset) {
    log_warn("xstartref appears before stream obj used to encode data: xref_offset = %ld; stream_start_offset = %ld",
	     xref_offset_orig, stream_start_offset);
    goto err;
  }

  xref_offset = xref_offset_orig + diff_len;
  log_debug("(old) xref_offset=%ld; (new) xref_offset=%ld", xref_offset_orig, xref_offset);
  template_p = end_of_line + 1;

  if (end_of_line[0] == '\r' && end_of_line[1] == '\n') {
    template_p++;
  }

  // write the value of xref_offset (i.e., updated startxref value)
  nbytes = snprintf(op, 11, "%ld\n", xref_offset);

  if (nbytes < 0) {
    log_warn("Fail to update the startxref value: snprintf fails (%d)", nbytes);
    goto err;
  }

  op += nbytes;
  return RCODE_OK;
  
 err:
  log_warn("error in fix xref table");
  return RCODE_ERROR;
}










/*
 * pdf_wrap embeds data of length dlen inside the stream objects of the PDF
 * document (length plen) that appears in the body of a HTTP msg, and
 * stores the result in the output buffer of size outsize
 *
 * pdf_wrap returns the length of the pdf document with the data embedded
 * inside, if succeed; otherwise, it returns -1 to indicate an error
 *
 *
 * Step 1: call compress to encode input data
 * Step 2: find the first stream object to embed the encoded data
 * Step 3: copy anything before stream object to output buffer
 * Step 4: create new stream object with the encoded data and append to output
 * Step 5: find xref table, copy stuff between stream object and xref table to output
 * Step 6: update xref table
 * Step 7: copy everything after xref table to output
 */

rcode_t
pdf_wrap (const char *data, size_t dlen, const char *pdf_template, size_t plen,
          char *outbuf, size_t outbufsize, size_t& bytes_written)
{
  // see rfc 1950 for zlib format, in addition to compressed data, we have
  // 2-byte compression method and flags + 4-byte dict ID + 4-byte ADLER32 checksum
  size_t data2size = 2*dlen+10; 
  const char *template_p, *template_end;
  char *op, *stream_start, *stream_end, *filter_start, *xrefp;
  char data2[data2size];
  size_t data2len = 0, size = 0, orig_len = 0, new_len = 0;
  int nbytes = 0;

  if (dlen > SIZE_T_CEILING || plen > SIZE_T_CEILING || outbufsize > SIZE_T_CEILING) {
    log_warn("dlen/plen/outbufsize too large");
    goto err;
  }

  /* Step 1: call compress to encode input data */
  data2len = compress((const uint8_t *)data, dlen, (uint8_t *)data2, data2size, c_format_zlib);

  if ((ssize_t) data2len < 0) {
    log_warn("compress failed and returned %" PriSSize_t, (ssize_t) data2len);
    goto err;
  }

  op = outbuf;       // current pointer for output buffer
  template_p = pdf_template;  // current pointer for http msg template
  template_end = pdf_template + plen;


  /* Step 2: find the first stream object to embed the encoded data */
  stream_start = str_in_binary(STREAM_BEGIN, STREAM_BEGIN_SIZE, template_p, template_end-template_p);

  if (stream_start == NULL) {
    log_warn("Cannot find stream in pdf");
    goto err;
  }

  stream_end = str_in_binary(STREAM_END, STREAM_END_SIZE, template_p, template_end-template_p);

  if (stream_end == NULL) {
    log_warn("Cannot find endstream in pdf");
    goto err;
  }

  filter_start = str_in_binary_rewind(" obj", 4, template_p, stream_start-template_p);

  if (filter_start == NULL) {
    log_warn("Cannot find obj\n");
    goto err;
  } 

  filter_start += 4;

  /* Step 3: copy anything before stream object to output buffer
     (including the word " obj")  */
  
  size = filter_start - template_p;
  
  if (memncpy(op, (outbuf+outbufsize)-op, (void *)template_p, size) != RCODE_OK) {
    log_warn("pdf_wrap (3): memncpy failed");
    goto err;
  }

  /* Step 4: create new stream object with the encoded data and append to output */

  op[size] = 0;
  op += size;

  // write meta-data for stream object
  nbytes = snprintf(op, outbufsize-(op-outbuf), "\n<<\n/Length %d\n/Filter /FlateDecode\n>>\nstream\n", (int)data2len);

  if (nbytes < 0) {
    log_warn("snprintf failed\n");
    goto err;
  }

  op += nbytes;
  
  // copy compressed data to outbuf 
  if (memncpy(op, (outbuf+outbufsize)-op, data2, data2len) != RCODE_OK) {
    log_warn("pdf_wrap (4): memncpy failed");
    goto err;
  }
  
  op += data2len;
  
  // write endstream to outbuf
  nbytes = snprintf(op, outbufsize-(op-outbuf), "\nendstream");

  if (nbytes < 0) {
    log_warn("snprintf failed\n");
    goto err;
  }

  op += nbytes;

  // orig_len: original length of stream obj  
  orig_len = stream_end - filter_start + STREAM_END_SIZE;
  // new_len: new length of stream obj  
  new_len  = op - outbuf - size;

  // done with encoding data
  template_p = stream_end+STREAM_END_SIZE;

  // updating the xref table:
  // for each obj entry: if the offset is > filter_start, adjust the offset
  // (note: end of xref table indicated by "trailer")
  // find the startxref tag and update the starting pos of the xref table, specified by startxref

  // example (xref table):
  // >> endobj
  // xref
  // 0 907
  // 0000000000 65535 f
  // 0000000529 00000 n
  // 0000000425 00000 n
  // [...]
  // 0002195303 00000 n
  // 0002195356 00000 n
  // trailer
  // << /Size 907
  // /Root 905 0 R
  // /Info 906 0 R
  // /ID [<BCFCBDE690EAD98E29E6BACDAD07F7B0> <BCFCBDE690EAD98E29E6BACDAD07F7B0>] >>
  // startxref
  // 2195623
  // %%EOF

  /* Step 5: find xref table, copy stuff between stream object and xref table to output */
  xrefp = str_in_binary("\nxref", 5, template_p, template_end-template_p);

  if (xrefp == NULL) {
    log_warn("Cannot find xref in pdf");
    goto err;
  }

  // copy the portion of pdf_template from tp to xrefp
  size = xrefp-template_p+1;  // note: add 1 for the newline in the xref pattern

  if (memncpy(op, (outbuf+outbufsize)-op, (void *)template_p, size) != RCODE_OK) {
    //the (size_t) cast is for the gitain mac build, which seems to think the castee is an int.
    log_warn("pdf_wrap (5): memncpy failed; buflen = %" PriSize_t "; size = %" PriSize_t, (size_t)((outbuf+outbufsize)-op), size);
    goto err;
  }

  template_p += size; 
  op += size;


  /* Step 6: update xref table */ 
  if (fix_xref_table(template_p, stream_start - pdf_template, template_end, op, outbuf, outbufsize, new_len - orig_len) != RCODE_OK) {
    log_warn("fix_xref_table failed");
    goto err;
  }

  /* Step 7: copy everything after xref table to output */

  // copy the rest of pdf_template to outbuf
  size = template_end - template_p;
  log_debug("copying the rest of pdf_template to outbuf (size %lu)",
            (unsigned long)size);

  if (memncpy(op, (outbuf+outbufsize)-op, (void *)template_p, size) != RCODE_OK) {
    log_warn("pdf_wrap (7): memncpy failed");
    goto err;
  }

  op += size;
  bytes_written = op-outbuf;
  return RCODE_OK;

 err:
  log_warn("error in pdf_wrap");
  return RCODE_ERROR;  
}





/*
 * pdf_unwrap is the inverse operation of pdf_wrap
 */
rcode_t
pdf_unwrap (const char *data, size_t dlen, char *outbuf, size_t outbufsize, size_t& bytes_written)
{
  const char *dp, *dlimit;
  char *op, *stream_start, *stream_end;
  size_t cnt, size, size2;

  int stream_obj_start_skip=0;
  int stream_obj_end_skip=0;

  if (dlen > SIZE_T_CEILING || outbufsize > SIZE_T_CEILING)
    goto err;

  dp = data;   // current pointer for data
  op = outbuf; // current pointer for outbuf
  cnt = 0;     // number of char decoded
  dlimit = data+dlen;

   
  while (dp < dlimit) {
    // find the next stream obj
    stream_start = str_in_binary(STREAM_BEGIN, STREAM_BEGIN_SIZE, dp, dlimit-dp);
    if (stream_start == NULL) {
      log_warn("Cannot find stream in pdf");
      goto err;
    }

    dp = stream_start + STREAM_BEGIN_SIZE;

    // stream_obj_start_skip = size of end-of-line (EOL) char(s) after the stream keyword
    if ( *dp == '\n' ) {
      stream_obj_start_skip = 1;
    } else {
      log_debug("Cannot find linefeed after the stream keyword");
    }

    dp = dp + stream_obj_start_skip;

    stream_end = str_in_binary(STREAM_END, STREAM_END_SIZE, dp, dlimit-dp);
    if (stream_end == NULL) {
      log_warn("Cannot find endstream in pdf");
      goto err;
    }

    // stream_obj_end_skip = size of end-of-line (EOL) char(s) at the end of stream obj
    if (*(stream_end-1) == '\n') {
      stream_obj_end_skip = 1;
    } 
    else {
      log_debug("Cannot find linefeed before the endstream keyword");
    }

    // compute the size of stream obj payload
    size = (stream_end-stream_obj_end_skip) - dp;
    size2 = decompress((const uint8_t *)dp, size, (uint8_t *)op, outbufsize);

    if ((int)size2 < 0) {
      log_warn("decompress failed; size2 = %d\n", (int)size2);
      goto err;
    } 
    else {
      op += size2;
      cnt = size2;
      break;  // done decoding
    }
  }

  bytes_written = cnt;
  return RCODE_OK;

 err:
  return RCODE_ERROR;
}




transmit_t
http_server_PDF_transmit (http_steg_t * s, struct evbuffer *source) {
  //char *secret = s->config->shared_secret;
  payloads pl = s->config->pl;
  transmit_t retval = NOT_TRANSMITTED;
  conn_t *conn = s->conn;
  char* headers = NULL;
  unsigned char* data = NULL, *body = NULL;


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

    if (source2raw(source, source_length, &data, data_length) != RCODE_OK) {
      log_warn("extracting raw to send failed");
      goto clean_up;
    }

    if (construct_pdf_body(pl, data, data_length, &body, body_length) != RCODE_OK) {
      log_warn("construct_pdf_body failed.");
      goto clean_up;
    }

    headers_length = construct_pdf_headers(HTTP_GET, NULL, NULL, NULL, body_length, headers);

    if(headers_length == 0){
      log_warn("construct_pdf_headers failed.");
      goto clean_up;
    }

    log_debug("http_server_PDF_transmit: data_length = %d  body_length = %d", (int)data_length, (int)body_length);

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
      profile_data("PDF", headers_length, body_length, source_length);
    }

    retval = TRANSMIT_GOOD;

  }


 clean_up:
  if(headers != NULL){ free(headers); }
  if(data != NULL){ free(data); }
  if(body != NULL){ free(body); }
  return retval;

}




recv_t 
http_client_PDF_receive (http_steg_t * s, struct evbuffer *dest, char* headers, size_t headers_length, char* response, size_t response_length) {
  const char *secret = s->config->shared_secret;
  recv_t retval = RECV_BAD;
  size_t data_length = 0, body_length = 0;
  unsigned char *data = NULL, *body = NULL;

  /* use them or .. */
  log_debug("response_length = %d %s %p", (int) response_length, secret, headers);
  body = (unsigned char*)&response[headers_length];
  body_length = response_length - headers_length;

  if (deconstruct_pdf_body(body, body_length, &data, data_length) != RCODE_OK)
    goto clean_up;

  retval = raw2dest(dest, data_length, data);

 clean_up:
  if(data != NULL){ free(data); }
  return retval;
}




size_t
construct_pdf_headers(int method, const char* path, const char* host, const char* cookie, size_t body_length, char* headers) {
  /* use them or .. */
  log_debug("path = %s; host = %s", path, host);

  size_t headers_length = MAX_HEADERS_SIZE;

  if (method == HTTP_GET) {
    if (gen_response_header(PDF_CONTENT_TYPE, cookie, 0, body_length, headers, headers_length, headers_length) != RCODE_OK)
      goto err;

  } else if(method == HTTP_POST){
    if (gen_post_header(PDF_CONTENT_TYPE, path, host, cookie, 0, body_length, headers, headers_length, headers_length) != RCODE_OK)
      goto err;

  } else {
    log_warn("Bad method %d to construct_pdf_headers (HTTP_GET = %d, HTTP_POST = %d)", method, HTTP_GET, HTTP_POST);
  }

  return headers_length;
  
 err:
  return 0;
}



rcode_t
construct_pdf_body(payloads &pl, unsigned char* data, size_t data_length, unsigned char**bodyp, size_t& body_len)
{
  char* pdf_template = NULL, *http_head_end;
  size_t pdf_template_size = 0;
  size_t http_head_len;
  char* outbuf = NULL;

  if (bodyp == NULL) {
    goto err;
  }

  if (get_payload(pl, HTTP_CONTENT_PDF, data_length, pdf_template, pdf_template_size) == RCODE_OK) {
    log_debug("Found HTTP PDF template with size %" PriSize_t, pdf_template_size);
  } else {
    log_warn("Unable to find HTTP PDF template");
    goto err;
  }
  
  http_head_end = strnstr(pdf_template, "\r\n\r\n", pdf_template_size);
  if (http_head_end == NULL) {
    log_warn("Unable to find the end of HTTP header");
    goto err;
  }
  
  http_head_len = http_head_end+4-pdf_template;

  outbuf = (char *) xzalloc(HTTP_MSG_BUF_SIZE_MAX);
  if (outbuf == NULL) {
    log_warn("buffer allocation failed");
    goto err;
  }
  
  log_debug("Calling pdf_wrap for data with length %" PriSize_t, data_length);
   
  if (pdf_wrap((const char *) data, data_length, http_head_end+4, pdf_template_size-http_head_len,
	       outbuf, HTTP_MSG_BUF_SIZE_MAX, body_len) != RCODE_OK) {
    goto err;
  }
  
  *bodyp = (unsigned char *) outbuf;
  return RCODE_OK;

 err:
  if (outbuf != NULL) free (outbuf);
  log_warn ("construct_pdf_body failed");
  return RCODE_ERROR;
  
}


rcode_t
construct_pdf_post_body(payloads &pl, unsigned char* data, size_t data_length, unsigned char**bodyp, size_t& body_len) 
{
  pdf_p cover = NULL;
  char* cover_template = NULL;
  size_t cover_template_size = 0;
  char* outbuf = NULL;

  if (bodyp == NULL) {
    goto err;
  }

  cover = get_cover_pdf(pl.pool_pdf, data_length);
  if (cover) {
    cover_template = (char *) (cover->bytes);
    cover_template_size = cover->size;
    log_debug("Found HTTP PDF template for pdf post [%s]", cover->path);
  } else {
    log_warn("Unable to find PDF template for pdf post");
    goto err;
  }

  outbuf = (char *) xzalloc(HTTP_MSG_BUF_SIZE_MAX);
  if (outbuf == NULL) {
    log_warn("buffer allocation failed");
    goto err;
  }
  
  log_debug("Calling pdf_wrap for data with length %" PriSize_t, data_length);
   
  if (pdf_wrap((const char *) data, data_length, cover_template, cover_template_size,
	       outbuf, HTTP_MSG_BUF_SIZE_MAX, body_len) != RCODE_OK) {
    goto err;
  }
  
  *bodyp = (unsigned char *) outbuf;
  return RCODE_OK;

 err:
  if (outbuf != NULL) free (outbuf);
  log_warn ("construct_pdf_post_body failed");
  return RCODE_ERROR;
}




rcode_t
deconstruct_pdf_body (unsigned char *body, size_t body_length, unsigned char** datap, size_t& data_len) {
  char *outbuf = NULL;

  if(datap != NULL){
    outbuf = (char *) xzalloc(HTTP_MSG_BUF_SIZE_MAX);
    if (outbuf == NULL) {
      log_warn("buffer allocation failed");
      goto err;
    }

    if (pdf_unwrap((const char *)body, body_length, outbuf, HTTP_MSG_BUF_SIZE_MAX, data_len) != RCODE_OK) {
      goto err;
    } else {
      *datap = (unsigned char *) outbuf;
    }
    return RCODE_OK;
  }

 err:
  if (outbuf != NULL) free (outbuf);
  log_warn("deconstruct_pdf_body failed");
  return RCODE_ERROR;
}



transmit_t
http_client_PDF_post_transmit (http_steg_t * s, struct evbuffer *source, conn_t *conn)
{
  transmit_t retval = NOT_TRANSMITTED;
  // image_pool_p pool = s->config->pl.pool;
  payloads pl = s->config->pl;
  struct evbuffer *dest = conn->outbound();
  size_t source_length = evbuffer_get_length(source);
  size_t headers_length = 0;
  unsigned char *data = NULL, *body = NULL;
  char *path = NULL, *headers = NULL;
  // char *secret = s->config->shared_secret;
  size_t body_length = 0;
  size_t data_length = 0;

  if (source2raw(source, source_length, &data, data_length) != RCODE_OK) {
    log_warn("extracting raw to send failed");
    goto clean_up;
  }

  headers = (char *)xzalloc(MAX_HEADERS_SIZE);

  if(headers == NULL){
    log_warn("header allocation failed.");
    goto clean_up;
  }

  // log_debug("secret = %s", secret);

  schemes_gen_post_request_path(s->config->pl, &path);

  if (construct_pdf_post_body(pl, data, data_length, &body, body_length) != RCODE_OK) {
    goto clean_up;
  }

  headers_length = construct_pdf_headers(HTTP_POST, path, HTTP_FAKE_HOST, NULL, body_length, headers);

  if(headers_length == 0){
    log_warn("construct_pdf_headers failed.");
    goto clean_up;
  }

  log_debug("pdf post headers = <headers>\n%s</headers>", headers);

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
  s->type = HTTP_CONTENT_PDF;
  s->have_transmitted = true;
  s->have_received = false;
  retval = TRANSMIT_GOOD;

  if(SCHEMES_PROFILING){
    profile_data("PDF", headers_length, body_length, source_length);
  }

 clean_up:
  if(headers != NULL)free(headers);
  if(data != NULL)free(data);
  if(body != NULL)free(body);
  if(path != NULL){ free(path); }
  return retval;

}





recv_t 
http_server_PDF_post_receive (http_steg_t * s, struct evbuffer *dest, char* headers, size_t headers_length, char* request, size_t request_length)
{
  recv_t retval = RECV_BAD;
  unsigned char *data = NULL, *body = NULL;
  size_t data_length = 0;
  size_t body_length = 0;
  const char *secret = s->config->shared_secret;

  /* the draconian flags we got going here... */
  log_debug("http_server_PDF_post_receive: request_length=%" PriSize_t " %s %p", request_length, secret, headers);

  body = (unsigned char*)&request[headers_length];
  body_length = request_length - headers_length;

  if (deconstruct_pdf_body(body, body_length, &data, data_length) != RCODE_OK)
    goto clean_up;

  retval = raw2dest(dest, data_length, data);

 clean_up:
  if(data != NULL)free(data);
  return retval;
}


