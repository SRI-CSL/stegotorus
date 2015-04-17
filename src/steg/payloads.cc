/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#include <ctype.h>
#include <time.h>

// for random number generator
#include <cstdlib>
#include <ctime>

#include "util.h"
#include "payloads.h"
#include "headers.h"
#include "compression.h"
#include "swfSteg.h"
#include "pdfSteg.h"
#include "strncasestr.h"
#include "jsutil.h"
#include "oshacks.h"




void 
free_payloads(payloads& pl)
{
  unsigned int r;

  log_warn("Unloading payloads\n");
  
  for (r = 0; r < pl.payload_count; r++) {
    free(pl.payloads[r]);
  }

  free_image_pool(pl.pool);

  free_pdf_pool(pl.pool_pdf);

}

void zero_payloads(payloads& pl){
  pl.max_JS_capacity = 0;
  pl.max_HTML_capacity = 0;
  pl.max_PDF_capacity = 0;
  pl.payload_count = 0;
  pl.pool = NULL;
  pl.pool_pdf = NULL;
}




/* XXX: even though we load there is no unload()... thus we never return this mem even at exit() */
void 
load_payloads(payloads& pl, const char* fname)
{
  FILE* f = NULL;
  char* curr_payload = NULL;
  char* temp_buf = NULL;
  pentry_header pentry;
  int bytes_read;

  log_warn("Loading payloads\n");

  srand(time(NULL));
  f = fopen(fname, "rb");

  if (f == NULL) {
    log_warn("cannot open trace file %s: exiting", fname);
    exit(1);
  }

  /* Report sizes of the structure, as these need to be the same across platforms (32/64bit etc) */
  /*
  log_debug("pentry.tot    = %" PRIuPTR, sizeof(pentry)));
  log_debug("pentry.ptype  @ %" PRIuPTR", = %" PRIuPTR, offsetof(pentry_header, ptype),  sizeof(pentry.ptype)));
  log_debug("pentry.length @ %" PRIuPTR", = %" PRIuPTR, offsetof(pentry_header, length), sizeof(pentry.length)));
  log_debug("pentry.port   @ %" PRIuPTR", = %" PRIuPTR, offsetof(pentry_header, port),   sizeof(pentry.port)));
  */

  temp_buf = (char *)xmalloc(HTTP_MSG_BUF_SIZE);
  memset(pl.payload_hdrs, 0, sizeof(pl.payload_hdrs));
  pl.payload_count = 0;

  while (pl.payload_count < MAX_PAYLOADS) {
    bytes_read = fread(&pentry, 1, sizeof(pentry), f);

    if (bytes_read < (int)sizeof(pentry)) {
      break;
    }

    log_debug("[%u] read %d bytes", pl.payload_count, bytes_read);

    // Fix byte order 
    pentry.length = ntohl(pentry.length);
    pentry.ptype = ntohs(pentry.ptype);

    log_debug("[%u] pentry.length = %u (0x%x)", pl.payload_count, pentry.length, pentry.length);
    log_debug("[%u] pentry.ptype = %u (0x%x)", pl.payload_count, pentry.ptype, pentry.ptype);

    if (pentry.length > HTTP_MSG_BUF_SIZE_MAX) {
      log_warn("pentry length larger than HTTP_MSG_BUF_SIZE_MAX %u > %u",
		 pentry.length, HTTP_MSG_BUF_SIZE_MAX);

      // skip to the next pentry
      if (fseek(f, pentry.length, SEEK_CUR)) {
        log_warn("skipping to next pentry failed");
	break; 	// give up
      }
      continue;       // keep on trying
    }

    curr_payload = (char *)xmalloc(pentry.length + 1);
    bytes_read = fread(curr_payload, 1, pentry.length, f);
    curr_payload[pentry.length] = 0;
    log_debug("[%u] read %d bytes", pl.payload_count, bytes_read);

    if (bytes_read < 0) {
      log_warn("pentry body read failed (%d)", bytes_read);
      goto err;
    }
    if (bytes_read < (int) pentry.length) {
      log_warn("short pentry body read %d < %u", bytes_read,  pentry.length);
      goto err;
    }
    if (bytes_read  > (int) pentry.length) {
      log_warn("long pentry body read %d > %u", bytes_read, pentry.length);
      goto err;
    }

    // fixed content length for gzip'd HTTP msg
    // fix_content_len returns -1, if no change to the msg
    // otherwise, it put the new HTTP msg (with hdr changed) in temp_buf
    // and returns the size of the new msg

    if (pentry.ptype == TYPE_HTTP_REQUEST && !validate_uri(curr_payload, (unsigned int) pentry.length)) {
      free(curr_payload);
      goto next;
    }

    // shouldn't happen due to check in the beggining of the while loop
    assert(pl.payload_count < MAX_PAYLOADS);

    // gets overwritten in the next block, if content-length needs to be fixed
    pl.payloads[pl.payload_count] = curr_payload; 

    if (pentry.ptype == TYPE_HTTP_RESPONSE) {
      if (pentry.length + 1 > HTTP_MSG_BUF_SIZE ||
	  CASECMPCONST(curr_payload, "HTTP/1.1 200 OK") != 0) {
	free(curr_payload);
	goto next;
      }
	
      bytes_read = fix_content_len(curr_payload, pentry.length, temp_buf, HTTP_MSG_BUF_SIZE);

      if (bytes_read > 0) {
	pentry.length = bytes_read;
	pl.payloads[pl.payload_count] = (char *)xmalloc(pentry.length + 1);

	//guaranteed to be safe as r > 0 and buf_len = pentry.length + 1
	if (memncpy(pl.payloads[pl.payload_count], pentry.length + 1, temp_buf, pentry.length) != RCODE_OK)
	  goto err;
	
	// Did not use curr_payload, as we use temp_buf
	free(curr_payload);
	log_debug("[%u] fix_content_len returns %d", pl.payload_count, bytes_read);
      } 
      else if (bytes_read == -2) {
	log_debug("err in fix_content_len");
	free(curr_payload);
	goto next;
      }
	
    }

    pl.payload_hdrs[pl.payload_count] = pentry;
    pl.payloads[pl.payload_count][pentry.length] = 0;
    pl.payload_count++;

  next:
    curr_payload = NULL;
    continue;
  err:
    free(curr_payload);
    curr_payload = NULL;
    break;
  } // while

  log_debug("loaded %d payloads from %s", pl.payload_count, fname);

  // Clean up temporary buffer */
  free(temp_buf);
  fclose(f);
}







int 
perturb_uri(char* line, size_t len) {
  char* buf;

  if (get_method(line, len) == HTTP_UNKNOWN)
    return -1;

  buf = strchr(line, ' ');

  if (buf++ == NULL)
    return -1;

  while (buf[0] != ' ') {

    if ((len - (unsigned int) (buf - line)) < sizeof(" HTTP/1.X\r\n")-1)
      return -1;

    if (buf[0] == '\r' && buf[1] == '\n')
      return -1;
    
    if (!strncasecmp(buf, ".html ", 6) || !strncasecmp(buf, ".htm ", 5) || !strncasecmp(buf, ".php ", 5)
	|| !strncasecmp(buf, ".jsp ", 5) || !strncasecmp(buf, ".asp ", 5))
      return 0;

    if (rand() % 3 == 0) 
      if (buf[0] >= '0' && buf[0] <= '9')
        buf[0] = (rand() % 8) + '1';
    
    buf++;
  }

  return 0;
}




bool 
validate_uri(char* line, size_t len) {
  char c;
  int j;
  
  if (get_method(line, len) == HTTP_UNKNOWN)
    return false;

  /* First skip over the method */
  for (j = 0; line[j] != ' '; j++) ;

  /* Skip over the space behind the method */
  j++;

  for (c = line[j]; c != ' '; c = line[++j]) {
    
    if (len - j < sizeof("HTTP/1.X\r\n")-1)
      return false;

    if (line[j] == '\r' && line[j+1] == '\n')
      return false;
   
    if (c == '%') {
      /* Escaped */
      if (!isxdigit(line[j+1]) || !isxdigit(line[j+2])) {
	return false;
      }
      
      j += 2;
    }
  }

  if (strncmp(line+j, " HTTP/1.0\r\n", sizeof(" HTTP/1.0\r\n")-1) != 0 &&
      strncmp(line+j, " HTTP/1.1\r\n", sizeof(" HTTP/1.1\r\n")-1) != 0)
    return false;

  return true;
}






/*
 * fix_content_len corrects the content-length for an HTTP msg that
 * has been ungzipped,
 *
 * the function returns -1 if no change to the HTTP msg has been made,
 * when the msg wasn't gzipped or -2 if an error has been encountered
 * if fix_content_len changes the msg header, it will put the new HTTP
 * msg in buf and returns the length of the new msg
 *
 * input:
 * payload - pointer to the (input) HTTP msg
 * payload_len - length of the (input) HTTP msg
 *
 * ouptut:
 * buf - pointer to the buffer containing the new HTTP msg
 * buf_len - length of buf
 * 
 */
int 
fix_content_len (char* payload, size_t payload_len, char *buf, size_t buf_len) {

  int gzip_flag=0, cl_flag=0, cl_zero_flag=0, r=0;
  char* ptr = payload;
  char* cl_ptr = payload;
  char* end;
  char *cp, *cl_end_ptr;
  size_t hdr_len, body_len, len;


  // note that the ordering between the content-length and the content-encoding
  // in an HTTP msg may be different for different msg 
  // if payload_len is larger than the size of our buffer,
  // stop and return -2

  if (payload_len > buf_len)  {
    log_debug("ERROR 1: fix_content_len: %" PriSize_t " %" PriSize_t "\n", payload_len, buf_len);
    goto err;
  }

  while (1) {
    if (ptr < payload || (size_t) (ptr - payload) >= payload_len)
      goto err;

    end = strnstr(ptr, "\r\n", payload_len - (ptr - payload));

    if (end == NULL) {
      log_debug("invalid header %" PriSize_t " %d %s", payload_len, (int) (ptr - payload), payload);
      goto err;
    }

    if (!CASECMPCONST(ptr, "Content-Encoding: gzip\r\n")) {
        gzip_flag = 1;
    } 
    else if (!CASECMPCONST(ptr, "Content-Length: 0")) {
        cl_zero_flag = 1;
    } 
    else if (!CASECMPCONST(ptr, "Content-Length:")) {
        cl_flag = 1;
        cl_ptr = ptr;
    }

    if (!strncmp(end, "\r\n\r\n", 4)){
      break;
    }
    ptr = end + 2;
  }

  
  if (!gzip_flag)
    return -1;

  // stop if zero content-length or content-length not found
  if (cl_zero_flag || ! cl_flag ) {
    log_debug("ERROR 2: fix_content_len: %d %d\n", cl_zero_flag, cl_flag);
    return -2;
  }
  
  // end now points to the end of the header, before "\r\n\r\n"
  cp = buf;
  body_len = (int) (payload_len - (end + 4 - payload));

  if (cl_ptr < payload || (size_t) (cl_ptr - payload) > payload_len)
    goto err;

  cl_end_ptr = strnstr(cl_ptr, "\r\n", payload_len - (cl_ptr - payload));

  if (cl_end_ptr == NULL) {
    log_debug("ERROR 3: fix_content_len: unable to find end of line for content-length");
    goto err;
  }

  // copy the part of the header before content-length
  len = (size_t) (cl_ptr - payload);
    
  if (memncpy(cp, buf_len - (cp - buf), payload, len) != RCODE_OK) {
    log_debug("ERROR 4: fix_content_len");
    goto err;
  }
  
  cp = cp + len;
    
  if (memncpy(cp, buf_len - (cp - buf), (void*) "Content-Length: ", sizeof ("Content-Length: ") - 1) != RCODE_OK) {
    log_debug("ERROR 5: fix_content_len");
    goto err;
  }
  
  cp = cp + sizeof("Content-Length: ") - 1;
  r = snprintf(cp, buf_len - (cp - buf),  "%" PriSize_t "\r\n", body_len);
  
  if (r < 0) {
    log_debug("ERROR 6: fix_content_len: sprintf fails");
    goto err;
  }
  
  cp = cp + r;

  // copy the part of the header between content-length and end of header
  len = (int)(end + 4  - (cl_end_ptr + 2));
  
  if (memncpy(cp, buf_len - (cp - buf), cl_end_ptr + 2, len) != RCODE_OK) {
    log_debug("ERROR 7: fix_content_len");
    goto err;
  }
  
  cp = cp + len;  
  hdr_len = cp-buf;
  
  // copy the HTTP body
  if (memncpy(cp, buf_len - (cp - buf), end + 4, body_len) != RCODE_OK) {
    log_debug("ERROR 8: fix_content_len");
    goto err;
  }
  
  return (hdr_len + body_len);

 err:
  log_warn("error in fix_content_len");
  return -2;
}



void 
gen_rfc_1123_date(char* buf, size_t buf_size) {
  time_t t = time(NULL);
  struct tm *my_tm = gmtime(&t);
  strftime(buf, buf_size, "Date: %a, %d %b %Y %H:%M:%S GMT\r\n", my_tm);
}



void 
gen_rfc_1123_expiry_date(char* buf, size_t buf_size) {
  time_t t = time(NULL) + rand() % 10000;
  struct tm *my_tm = gmtime(&t);
  strftime(buf, buf_size, "Expires: %a, %d %b %Y %H:%M:%S GMT\r\n", my_tm);
}





rcode_t 
gen_response_header(const char* content_type, const char *cookie, int gzip, size_t length, 
		    char* buf, size_t buflen, size_t& hdrlen) {
  char* ptr;
  // conservative assumption here.... 
  size_t required_space = 512;

  //need space for cookie if supplied
  if(cookie != NULL){
    required_space += strlen(cookie);
  }
  
  if (buflen < required_space) {
    log_warn("gen_response_header: buflen too small (needs %" PriSize_t ")", required_space);
    return RCODE_ERROR;
  }

  sprintf(buf, "HTTP/1.1 200 OK\r\n");
  ptr = buf + sizeof("HTTP/1.1 200 OK\r\n")-1;
  gen_rfc_1123_date(ptr, buflen - (ptr - buf));
  ptr = ptr + strlen(ptr);

  sprintf(ptr, "Server: Apache\r\n");
  ptr = ptr + strlen(ptr);

  switch(rand() % 9) {
  case 1:
    sprintf(ptr, "Vary: Cookie\r\n");
    ptr = ptr + strlen(ptr);
    break;

  case 2:
    sprintf(ptr, "Vary: Accept-Encoding, User-Agent\r\n");
    ptr = ptr + strlen(ptr);
    break;

  case 3:
    sprintf(ptr, "Vary: *\r\n");
    ptr = ptr + strlen(ptr);
    break;

  }

  if (rand() % 4 == 0) {
    gen_rfc_1123_expiry_date(ptr, buflen - (ptr - buf));
    ptr = ptr + strlen(ptr);
  }

  if(cookie){
    /* not very safe */
    sprintf(ptr, "Set-Cookie: %s\r\n", cookie);
    ptr = ptr + strlen(ptr);
  }
  

  if (gzip) 
    sprintf(ptr, "Content-Length: %" PriSize_t "\r\nContent-Encoding: gzip\r\nContent-Type: %s\r\n", length, content_type);
  else
    sprintf(ptr, "Content-Length: %" PriSize_t "\r\nContent-Type: %s\r\n", length, content_type);
    
  ptr += strlen(ptr);

  sprintf(ptr, "Connection: Keep-Alive\r\n\r\n");
  //  sprintf(ptr, "Connection: close\r\n\r\n");

  ptr += strlen(ptr);
  hdrlen =  ptr - buf;

  return RCODE_OK;
}


rcode_t 
gen_post_header(const char* content_type, const char *path, const char *host, const char *cookie, int gzip, 
		size_t length, char* buf, size_t buflen, size_t& header_len) {
  char* ptr;
  // conservative assumption here.... 
  size_t required_space = 512;
  //need space for cookie if supplied
  size_t cookie_length = 0;


  if(cookie != NULL){
    cookie_length = strlen(cookie);
  }
  
  if (buflen < required_space + cookie_length ) {
    log_warn("gen_post_header: buflen too small (needs %" PriSize_t " of which %" PriSize_t " is for the cookie)", required_space + cookie_length, cookie_length);
    goto err;
  }

  /*
   * HTTP/1.1 *requires* a HOST header
   * (actually any request in the form of "<method> <uri> HTTP/<ver>")
   */

  if (host == NULL) {
    log_warn("host header not found");
    goto err;
  }

  snprintf(buf, buflen, "POST %s HTTP/1.1\r\nHost: %s\r\n", path, host);
  ptr = buf + strlen(buf);
  
  gen_rfc_1123_date(ptr, buflen - (ptr - buf));
  ptr = ptr + strlen(ptr);

  //sprintf(ptr, "Host: api.opencalais.com\r\n");
  //ptr = ptr + strlen(ptr);

  if(cookie){
    /* not very safe */
    sprintf(ptr, "Cookie: %s\r\n", cookie);
    ptr = ptr + strlen(ptr);
  }

  if (gzip) 
    sprintf(ptr, "Content-Length: %" PriSize_t "\r\nContent-Encoding: gzip\r\nContent-Type: %s\r\n", length, content_type);
  else
    sprintf(ptr, "Content-Length: %" PriSize_t "\r\nContent-Type: %s\r\n", length, content_type);
    
  ptr += strlen(ptr);
  sprintf(ptr, "Connection: Keep-Alive\r\n\r\n");
  ptr += strlen(ptr);
  header_len = ptr - buf;
  return RCODE_OK;

 err:
  return RCODE_ERROR;
}






rcode_t
parse_client_headers(char* inbuf, size_t inbuf_len, char* outbuf, size_t outbuf_len, size_t& bytes_written) {
  // client-side
  // remove host: field
  // remove referrer fields?

  size_t outlen = 0;
  char* end;

  if (outbuf_len < inbuf_len)
    goto err;

  while (1) {
    end = strnstr(inbuf, "\r\n", inbuf_len);

    if (end == NULL) {
      log_warn("invalid client header %" PriSize_t " %s", inbuf_len, inbuf);
      break;
    }

    if (!CASECMPCONST(inbuf, "Host") || !CASECMPCONST (inbuf, "Referer:") || !CASECMPCONST(inbuf, "Cookie:")) {
      goto next;
    }
    
    if (memncpy(outbuf + outlen, outbuf_len - outlen, inbuf, end - inbuf + 2) != RCODE_OK)
      goto err;

    outlen += (size_t) (end - inbuf) + 2;

  next:
    if (!STRNCMPCONST(end, "\r\n\r\n")){
      break;
    }

    if ((size_t) (end - inbuf + 2) > inbuf_len)
      goto err;

    inbuf_len = inbuf_len - (size_t) (end - inbuf) - 2; 
    inbuf = end + 2;
  }

  bytes_written = outlen;
  return RCODE_OK;

 err:
  return RCODE_ERROR;

  // server-side
  // fix date fields
  // fix content-length
}






/* first line is of the form....
   GET /xX/xXXX.swf[?yYYY] HTTP/1.1\r\n
*/

http_content_t  
find_uri_type(char* buf_orig, size_t buflen) {
  http_content_t retval = HTTP_CONTENT_NONE;
  bool ispost = false;
  char *uri, *ext = NULL, *uri_end;
  char *buf = (char *)xmalloc(buflen+1);

  if(buf == NULL){
    goto clean_up;
  }

  if (memncpy(buf, buflen+1, buf_orig, buflen) != RCODE_OK)
    goto clean_up;

  buf[buflen] = 0;
  
  if (CASECMPCONST(buf, "GET") != 0 && CASECMPCONST(buf, "POST") != 0) {
    goto clean_up;
  }

  if(CASECMPCONST(buf, "POST") == 0){ ispost = true; }

  uri = strchr(buf, ' ') + 1;

  if (uri == NULL) {
    log_warn("invalid URL");
    goto clean_up;
  }

  uri_end = strchr(uri, ' ');

  if (uri_end == NULL) {
    log_warn("unterminated uri");
    goto clean_up;
  }

  uri_end[0] = 0;  
  ext = strrchr(uri, '/');

  if (ext == NULL) {
    log_warn("no / in url: find_uri_type...");
    goto clean_up;
  }

  ext = strchr(ext, '.');

  /* n.b. JSON must preceed JS  */
  if (ext == NULL || !CASECMPCONST(ext, ".html") || !CASECMPCONST(ext, ".htm") || !CASECMPCONST(ext, ".php")
      || !CASECMPCONST(ext, ".jsp") || !CASECMPCONST(ext, ".asp")){
    retval = HTTP_CONTENT_HTML;
  }  else if (!CASECMPCONST(ext, ".json") || ispost){
    retval = HTTP_CONTENT_JSON;
  } else if (!CASECMPCONST(ext, ".js")) {
    retval = HTTP_CONTENT_JAVASCRIPT;
  } else if (!CASECMPCONST(ext, ".pdf")) {
    retval = HTTP_CONTENT_PDF;
  } else if (!CASECMPCONST(ext, ".swf")) {
    retval = HTTP_CONTENT_SWF;
  } else if (!CASECMPCONST(ext, ".jpeg") || !CASECMPCONST(ext, ".jpg")) {
    retval = HTTP_CONTENT_JPEG;
  } else if (!CASECMPCONST(ext, ".exe")) {
    retval = HTTP_CONTENT_RAW;
  }  

 clean_up:
  if(retval == HTTP_CONTENT_NONE){
    log_info("find_uri_type: UNKNOWN TYPE\n%s\n", buf_orig);
  }
  free(buf);
  return retval;
}




rcode_t
find_client_payload(payloads& pl, char* buf, size_t buflen, uint16_t type, size_t& bytes_written) {
  unsigned int r = rand() % pl.payload_count;
  unsigned int cnt = 0;
  char* inbuf = NULL;
  size_t len = 0;

  while (1) {
    pentry_header* p = &pl.payload_hdrs[r];
    if (p->ptype == type) {
      inbuf = pl.payloads[r];

      if (p->length < 3 || CASECMPCONST(inbuf, "GET") != 0) {
	goto next;
      }

      int current_type = find_uri_type(inbuf, p->length);
      
      if (current_type != HTTP_CONTENT_SWF &&
          current_type != HTTP_CONTENT_HTML &&
	  current_type != HTTP_CONTENT_JAVASCRIPT &&
	  current_type != HTTP_CONTENT_PDF &&
          current_type != HTTP_CONTENT_JPEG) {
	goto next;
      }

      // ensures outbuf_len >= inbuf_len in parse_client_headers
      if (p->length > buflen) {
	log_debug("BUFFER TOO SMALL: %d %" PriSize_t, p->length, buflen);
	goto next;
      }

      len = p->length;
      break;
    }
  next:
    r = (r+1) % pl.payload_count;

    // no matching payloads...
    if (cnt++ == pl.payload_count) {
      log_debug("no matching payloads");
      return RCODE_ERROR;
    }
  }

  inbuf[len] = 0;

  // clean up the buffer...
  return parse_client_headers(inbuf, len, buf, buflen, bytes_written);
}



/*
 * has_eligible_HTTP_content() identifies if the input HTTP message 
 * contains a specified type of content, used by a steg module to
 * select candidate HTTP message as cover traffic
 */

// for java_script, there are two cases:
// 1) if content-type: has one of the following values
//       text/javascript 
//       application/x-javascript
//       application/javascript
// 2) content-type: text/html and 
//    HTTP body contains <script type="text/javascript"> ... </script>
// #define CONTENT_JAVASCRIPT		1 (for case 1)
// #define CONTENT_HTML_JAVASCRIPT	2 (for case 2)
//
// for pdf, we look for the msgs whose content-type: has one of the
// following values
// 1) application/pdf
// 2) application/x-pdf
// 

int 
has_eligible_HTTP_content (char* buf, size_t len, int type) {
  char* ptr = buf;
  char* matchptr;
  int tj_flag=0, th_flag=0, ce_flag=0, te_flag=0, http304Flag=0, cl_zero_flag=0, pdf_flag=0, swf_flag=0; 
  char* end, *cp, *xp, *xp2, *sxp, *sxp2;

  if (type != HTTP_CONTENT_JAVASCRIPT &&
      type != HTTP_CONTENT_HTML &&
      type != HTTP_CONTENT_PDF && type != HTTP_CONTENT_SWF)
    return 0;

  // assumption: buf is null-terminated
  if (!strnstr(buf, "\r\n\r\n", len))
    return 0;


  while (1) {

    assert((size_t) (ptr - buf) < len && (ssize_t) (ptr - buf) >= 0);
    end = strnstr(ptr, "\r\n", len - (ptr - buf));

    if (end == NULL) {
      break;
    }

    if (!CASECMPCONST(ptr, "Content-Type:")) {	
      if (!CASECMPCONST(ptr+14, "text/javascript") || 
	  !CASECMPCONST(ptr+14, "application/javascript") || 
	  !CASECMPCONST(ptr+14, "application/x-javascript")) {
	tj_flag = 1;
      }
      if (!CASECMPCONST(ptr+14, "text/html")) {
	th_flag = 1;
      }
      if (!CASECMPCONST(ptr+14, "application/pdf") || 
	  !CASECMPCONST(ptr+14, "application/x-pdf")) {
	pdf_flag = 1;
      }
      if (!CASECMPCONST(ptr+14, "application/x-shockwave-flash")) {
	swf_flag = 1;
      }

    } else if (!CASECMPCONST(ptr, "Content-Encoding: gzip")) {
      //      gzip_flag = 1; // commented out as variable is set but never read and ubuntu compiler complains
    } else if (!CASECMPCONST(ptr, "Content-Encoding:")) { // content-encoding that is not gzip
      ce_flag = 1;
    } else if (!CASECMPCONST(ptr, "Transfer-Encoding:")) {
      te_flag = 1;
    } else if (!STRNCMPCONST(ptr, "HTTP/1.1 304 ")) {
      http304Flag = 1;
    } else if (!CASECMPCONST(ptr, "Content-Length: 0")) {
      cl_zero_flag = 1;
    }
    
    if (!STRNCMPCONST(end, "\r\n\r\n")){
      break;
    }
    ptr = end+2;
  }


  if (type == HTTP_CONTENT_JAVASCRIPT || type == HTTP_CONTENT_HTML) {
    // empty body if it's HTTP not modified (304) or zero content-length
    if (http304Flag || cl_zero_flag) return 0; 

    // for now, we're not dealing with transfer-encoding (e.g., chunked)
    // or content-encoding that is not gzip
    // if (te_flag) return 0;
    if (te_flag || ce_flag) return 0;

    if (tj_flag && ce_flag && end != NULL) {
      log_debug("(JS) gzip flag detected with hdr len %d", (int)(end-buf+4));
    } else if (th_flag && ce_flag && end != NULL) {
      log_debug("(HTML) gzip flag detected with hdr len %d", (int)(end-buf+4));
    }

    // case 1
    if (tj_flag) return 1; 

    // case 2: check if HTTP body contains <script type="text/javascript">
    if (th_flag) {
      assert((size_t) (ptr - buf) < len && (ssize_t) (ptr - buf) >= 0);
      matchptr = strnstr(ptr, "<script type=\"text/javascript\">", len - (ptr - buf));
      if (matchptr != NULL) {
        return 2;
      }
    }
  }

  if (type == HTTP_CONTENT_PDF && pdf_flag) {
    // reject msg with empty body: HTTP not modified (304) or zero content-length
    if (http304Flag || cl_zero_flag) return 0; 

    // for now, we're not dealing with transfer-encoding (e.g., chunked)
    // or content-encoding that is not gzip
    // if (te_flag) return 0;
    if (te_flag || ce_flag) return 0;

    // check if HTTP body contains "endstream";
    // strlen("endstream") == 9
    cp = str_in_binary("endstream", 9, ptr, buf+len-ptr);
    if (cp == NULL) return 0;

    // check if one can find exactly one xref table after endstream
    xp = str_in_binary("\nxref", 5, ptr, buf+len-ptr);
    if (xp == NULL || xp < cp) return 0;
    sxp = str_in_binary("startxref", 9, ptr, buf+len-ptr);
    if (sxp == NULL || sxp < cp || sxp < xp) return 0;

    // and no more xref table after that
    xp2 = str_in_binary("\nxref", 5, xp+5, buf+len-xp-5);
    sxp2 = str_in_binary("startxref", 9, sxp+9, buf+len-sxp-9);

    if (xp2 != NULL || sxp2 != NULL) return 0;
    return 1;
  }
  
  if (type == HTTP_CONTENT_SWF && swf_flag == 1) 
    return 1;

  return 0;
}



size_t
capacity_PDF (char* buf, size_t len) {
  char *bp, *buf_end, *stream_start, *stream_end;
  size_t capacity = 0;

  if (buf == NULL)
    goto done;

  buf_end = buf + len;

  // jump to the beginning of the body of the HTTP message
  bp = strnstr(buf, "\r\n\r\n", len);

  // cannot find the separator between HTTP header and HTTP body
  if (bp == NULL) {
    return 0;
  }

  bp = bp + 4;

  if (bp >= buf_end)
    goto done;

  stream_start = str_in_binary(STREAM_BEGIN, STREAM_BEGIN_SIZE, bp, buf_end-bp);

  if (stream_start == NULL)
    goto done;

  bp = stream_start+STREAM_BEGIN_SIZE;
  stream_end = str_in_binary(STREAM_END, STREAM_END_SIZE, bp, buf_end-bp);

  if (stream_end == NULL)
    goto done;

  capacity = (PDF_MAX_AVAIL_SIZE-1);

 done:
  return capacity;
}




/*
 * init_payload_pool initializes the arrays pertaining to 
 * message payloads for the specified content type
 *
 * specifically, it populates the following arrays
 * static int init_type_payload[MAX_CONTENT_TYPE];
 * static int type_payload_count[MAX_CONTENT_TYPE];
 * static int type_payload[MAX_CONTENT_TYPE][MAX_PAYLOADS];
 * static int type_payload_cap[MAX_CONTENT_TYPE][MAX_PAYLOADS];
 *
 * input:
 * len - max length of payload
 * type - ptype field value in pentry_header
 * content_type - (e.g, HTTP_CONTENT_JAVASCRIPT for java_script content)
 */

rcode_t
init_JS_payload_pool(payloads& pl, uint32_t len, uint16_t type, uint32_t min_capacity) {
  // stat for usable payload
  uint32_t min_payload_size = 0, max_payload_size = 0;
  uint32_t sum_payload_size = 0;
  uint32_t min_payload_cap = 0, max_payload_cap = 0;
  uint32_t sum_payload_cap = 0;
  uint32_t cap = 0;

  char tmp_buf[HTTP_MSG_BUF_SIZE];
  int cnt = 0, mode = 0;
  size_t new_msg_len = 0;
  unsigned int content_type = HTTP_CONTENT_JAVASCRIPT;
  unsigned int r;
  pentry_header* p;
  char* msgbuf;

  if (pl.payload_count == 0) {
    log_debug("payload_count == 0; forgot to run load_payloads()?");
    return RCODE_ERROR;
  }

  if (PERTURB_JS) {
    // randomize the seed
    srand((unsigned)time(0));
  }
 
  for (r = 0; r < pl.payload_count; r++) {
    p = &pl.payload_hdrs[r];
    if (p->ptype != type || p->length > len) {
      continue;
    }

    msgbuf = pl.payloads[r];

    mode = has_eligible_HTTP_content(msgbuf, p->length, HTTP_CONTENT_JAVASCRIPT);

    if (mode != CONTENT_JAVASCRIPT) continue;

    // removing comments from JS
    if (REMOVE_JS_COMMENT) {
      if (remove_js_comment(msgbuf, p->length, tmp_buf, HTTP_MSG_BUF_SIZE, new_msg_len) != RCODE_OK) {
        continue;
      }

      if (((uint32_t)new_msg_len) < p->length) {
        // update hdr &pl.payload_hdrs[r] with the new length
        p->length = new_msg_len;
      }
    }


    // replacing non-hex alphabet char with non-hex alphabet ones probabilistically
    if (PERTURB_JS) {
      if (perturb_JS(msgbuf, p->length, tmp_buf, HTTP_MSG_BUF_SIZE, new_msg_len) != RCODE_OK) {
        continue;
      }

      if (((uint32_t)new_msg_len) < p->length) {
        // update hdr &pl.payload_hdrs[r] with the new length
        p->length = new_msg_len;
      }
    }
    
    
    cap = capacity_JS(msgbuf, p->length, mode);
    if (cap <  JS_DELIMITER_SIZE*2)
      continue;

    cap = (cap - JS_DELIMITER_SIZE*2)/2;
    
    if (cap > min_capacity) {
      pl.type_payload_cap[content_type][cnt] = cap; // (cap-JS_DELIMITER_SIZE)/2;
      // because we use 2 hex char to encode every data byte, the available
      // capacity for encoding data is divided by 2
      pl.type_payload[content_type][cnt] = r;
      cnt++;
      
      // update stat
      if (cnt == 1) {
	min_payload_size = p->length; max_payload_size = p->length;
	min_payload_cap = cap; max_payload_cap = cap;
      } 
      else {
	if (min_payload_size > p->length) min_payload_size = p->length; 
	if (max_payload_size < p->length) max_payload_size = p->length; 
	if (min_payload_cap > cap) min_payload_cap = cap;
	if (max_payload_cap < cap) {
	  max_payload_cap = cap;
	}
	
      }
      sum_payload_size += p->length; sum_payload_cap += cap;
    }
  }

  pl.max_JS_capacity = max_payload_cap;
  pl.init_type_payload[content_type] = 1;
  pl.type_payload_count[content_type] = cnt;
  log_debug("init_payload_pool: type_payload_count for content_type %d = %d",
     content_type, pl.type_payload_count[content_type]); 
  log_debug("min_payload_size = %d", min_payload_size); 
  log_debug("max_payload_size = %d", max_payload_size); 
  log_debug("avg_payload_size = %f", (float)sum_payload_size/(float)(cnt == 0 ? 1 : cnt)); 
  log_debug("min_payload_cap  = %d", min_payload_cap); 
  log_debug("max_payload_cap  = %d", max_payload_cap); 
  log_debug("avg_payload_cap  = %f", (float)sum_payload_cap/(float)(cnt == 0 ? 1 : cnt)); 
  return RCODE_OK;
}





rcode_t  
init_HTML_payload_pool(payloads& pl, uint32_t len, uint16_t type, uint32_t min_capacity) {

  // stat for usable payload
  uint32_t min_payload_size = 0, max_payload_size = 0; 
  uint32_t sum_payload_size = 0;
  uint32_t min_payload_cap = 0, max_payload_cap = 0;
  uint32_t sum_payload_cap = 0;
  uint32_t cap = 0;
  int cnt = 0, mode = 0;
  size_t new_msg_len = 0;
  unsigned int content_type = HTTP_CONTENT_HTML;
  unsigned int r;

  char tmp_buf[HTTP_MSG_BUF_SIZE];
  pentry_header* p;
  char* msgbuf = NULL;

  if (pl.payload_count == 0) {
    log_debug("payload_count == 0; forgot to run load_payloads()?");
    return RCODE_ERROR;
  }

  if (PERTURB_HTML_JS) {
    // randomize the seed
    srand((unsigned)time(0));
  }

  for (r = 0; r < pl.payload_count; r++) {
    p = &pl.payload_hdrs[r];
    if (p->ptype != type || p->length > len) {
      continue;
    }

    msgbuf = pl.payloads[r];
    mode = has_eligible_HTTP_content(msgbuf, p->length, HTTP_CONTENT_HTML);

    if (mode != CONTENT_HTML_JAVASCRIPT) continue;

    // removing comments from JS embedded in HTML
    if (REMOVE_HTML_JS_COMMENT) {
      if (remove_js_comment_in_HTML(msgbuf, p->length, tmp_buf, HTTP_MSG_BUF_SIZE, new_msg_len) != RCODE_OK) {
        continue;
      }

      if (((unsigned int)new_msg_len) < p->length) {
        // update hdr &pl.payload_hdrs[r] with the new length
        p->length = new_msg_len;
      }
    }


    // replacing non-hex alphabet char with non-hex alphabet ones probabilistically
    if (PERTURB_HTML_JS) {
      if (perturb_JS_in_HTML(msgbuf, p->length, tmp_buf, HTTP_MSG_BUF_SIZE, new_msg_len) != RCODE_OK) {
        continue;
      }

      if (((unsigned int)new_msg_len) < p->length) {
        // update hdr &pl.payload_hdrs[r] with the new length
        p->length = new_msg_len;
      }
    }

    cap = capacity_JS(msgbuf, p->length, mode);
    if (cap <  JS_DELIMITER_SIZE*2) 
      continue;

    cap = (cap - JS_DELIMITER_SIZE*2)/2;
      
    if (cap > min_capacity) {
      pl.type_payload_cap[content_type][cnt] = cap; // (cap-JS_DELIMITER_SIZE)/2;
      // because we use 2 hex char to encode every data byte, the available
      // capacity for encoding data is divided by 2
      pl.type_payload[content_type][cnt] = r;
      cnt++;
	
      // update stat
      if (cnt == 1) {
	min_payload_size = p->length; max_payload_size = p->length;
	min_payload_cap = cap; max_payload_cap = cap;
      } 
      else {
	if (min_payload_size > p->length) min_payload_size = p->length; 
	if (max_payload_size < p->length) max_payload_size = p->length; 
	if (min_payload_cap > cap) min_payload_cap = cap;
	if (max_payload_cap < cap) {
	  max_payload_cap = cap;
	}
	
      }
      sum_payload_size += p->length; sum_payload_cap += cap;
    }
  }

  pl.max_HTML_capacity = max_payload_cap;
  pl.init_type_payload[content_type] = 1;
  pl.type_payload_count[content_type] = cnt;
  log_debug("init_payload_pool: type_payload_count for content_type %d = %d",
     content_type, pl.type_payload_count[content_type]); 
  log_debug("min_payload_size = %d", min_payload_size); 
  log_debug("max_payload_size = %d", max_payload_size); 
  log_debug("avg_payload_size = %f", (float)sum_payload_size/(float)(cnt == 0 ? 1 : cnt)); 
  log_debug("min_payload_cap  = %d", min_payload_cap); 
  log_debug("max_payload_cap  = %d", max_payload_cap); 
  log_debug("avg_payload_cap  = %f", (float)sum_payload_cap/(float)(cnt == 0 ? 1 : cnt)); 
  return RCODE_OK;
}





rcode_t
init_PDF_payload_pool(payloads& pl, uint32_t len, uint16_t type, uint32_t min_capacity)
{

  // stat for usable payload
  uint32_t min_payload_size = 0, max_payload_size = 0; 
  uint32_t sum_payload_size = 0;
  uint32_t min_payload_cap = 0, max_payload_cap = 0;
  uint32_t sum_payload_cap = 0;
  uint32_t cap;

  int cnt = 0, mode = 0;
  unsigned int r;
  pentry_header* p;
  char* msgbuf;
  unsigned int content_type = HTTP_CONTENT_PDF;
  

  if (pl.payload_count == 0) {
     log_warn("payload_count == 0; forgot to run load_payloads()?");
     return RCODE_ERROR;
  }

  for (r = 0; r < pl.payload_count; r++) {
    p = &pl.payload_hdrs[r];
    if (p->ptype != type || p->length > len) {
      continue;
    }

    msgbuf = pl.payloads[r];

    mode = has_eligible_HTTP_content(msgbuf, p->length, HTTP_CONTENT_PDF);
    if (mode > 0) {
      // use capacity_PDF() to find out the amount of data that we
      // can encode in the pdf doc 
      // cap = min_capacity+1;
      cap = capacity_PDF(msgbuf, p->length);
      if (cap > min_capacity) {
	pl.type_payload_cap[content_type][cnt] = cap;
	pl.type_payload[content_type][cnt] = r;
	cnt++;
	
	// update stat
	if (cnt == 1) {
	  min_payload_size = p->length; max_payload_size = p->length;
	  min_payload_cap = cap; max_payload_cap = cap;
	} 
	else {
	  if (min_payload_size > p->length) min_payload_size = p->length; 
	  if (max_payload_size < p->length) max_payload_size = p->length; 
	  if (min_payload_cap > cap) min_payload_cap = cap;
	  if (max_payload_cap < cap) max_payload_cap = cap;
	}
	sum_payload_size += p->length; sum_payload_cap += cap;
      }
    }
  }

  pl.max_PDF_capacity = max_payload_cap;
  pl.init_type_payload[content_type] = 1;
  pl.type_payload_count[content_type] = cnt;
  log_debug("init_payload_pool: type_payload_count for content_type %d = %d",
     content_type, pl.type_payload_count[content_type]); 
  log_debug("min_payload_size = %d", min_payload_size); 
  log_debug("max_payload_size = %d", max_payload_size); 
  log_debug("avg_payload_size = %f", (float)sum_payload_size/(float)(cnt == 0 ? 1 : cnt)); 
  log_debug("min_payload_cap  = %d", min_payload_cap); 
  log_debug("max_payload_cap  = %d", max_payload_cap); 
  log_debug("avg_payload_cap  = %f", (float)sum_payload_cap/(float)(cnt == 0 ? 1 : cnt)); 
  return RCODE_OK;
}





bool 
validate_swf(char* in_swf, unsigned int in_sz) {
  unsigned int nbits = ((in_swf[0]  & 0xf8) >> 3) * 4 + 5;
  unsigned int skip = nbits / 8;


  if (nbits % 8 > 0)
    skip++;

  if (in_sz < skip+4)
    return false;

  in_swf += (skip + 4);
  in_sz -= (skip + 4);
  

  do {    
    unsigned int tag = (((short*) in_swf)[0] & 0xffc0) >> 6;
    unsigned int taglen = (((short*) in_swf)[0] & 0x3f);
    
    if (tag == 0)
      break;
    else if (tag > 100) {
      log_debug("returning false %d\n", tag);
      return false;
    }

    if (in_sz >= 2) {
      in_swf += 2;
      in_sz -= 2;
    }
    else {
      return false;
    }

    // long header
    if (taglen == 0x3f) {      
      taglen = * ((unsigned int*) in_swf);
      if (in_sz >= 4) {
	in_swf += 4;
	in_sz -= 4;
      }
      else {
	return false;
      }      
    }

    if (in_sz < taglen) {
      return false;
    }

    in_swf = in_swf + taglen;
    in_sz -= taglen; 

  } while (1);

  return true;
}




rcode_t
init_SWF_payload_pool(payloads& pl, uint32_t len, uint16_t type, uint32_t /*unused */)
{
  // stat for usable payload
  uint32_t min_payload_size = 0, max_payload_size = 0, sum_payload_size = 0, cnt = 0;
  unsigned int r;
  int mode, inflated_swf_len;
  pentry_header* p;
  char* msgbuf, *swf, *inflated_swf;
  uint32_t content_type = HTTP_CONTENT_SWF, in_swf_len, tmp_buf_len;


  if (pl.payload_count == 0) {
     log_warn("payload_count == 0; forgot to run load_payloads()?");
     return RCODE_ERROR;
  }

  for (r = 0; r < pl.payload_count; r++) {
    p = &pl.payload_hdrs[r];
    if (p->ptype != type || p->length > len) {
      continue;
    }

    msgbuf = pl.payloads[r];
    // found a payload corr to the specified content_type

    mode = has_eligible_HTTP_content(msgbuf, p->length, HTTP_CONTENT_SWF);
    if (mode <= 0)
      continue;

    swf = strnstr(msgbuf, "\r\n\r\n", p->length) + 4;
    if (memcmp(swf, "CWS", 3))
      continue;

    in_swf_len = p->length - (swf - msgbuf);

    /* get ready to decompress the body */
    tmp_buf_len = 4*in_swf_len + 512;
    inflated_swf = (char *)xmalloc(tmp_buf_len);

    /* decompress the body */
    inflated_swf_len = decompress((unsigned char*) swf+8, (size_t) in_swf_len-8, 
				  (unsigned char*) inflated_swf, tmp_buf_len);

    if (inflated_swf_len < 0)  {
      free(inflated_swf);
      continue;
    }

    
    if (!validate_swf(inflated_swf, inflated_swf_len)) {
      log_debug("dropping invalid swf %d\n", inflated_swf_len);
      free(inflated_swf);
      continue;
    }

      
    free(pl.payloads[r]);
    pl.payloads[r] = inflated_swf;
    p->length = inflated_swf_len;
    pl.type_payload[content_type][cnt] = r;
    
    cnt++;
    // update stat
    if (cnt == 1) {
      min_payload_size = p->length; 
      max_payload_size = p->length;
    } 
    else {
      if (min_payload_size > p->length) 
	min_payload_size = p->length; 
      if (max_payload_size < p->length) 
	max_payload_size = p->length; 
    }
    sum_payload_size += p->length;
  }
  
  pl.init_type_payload[content_type] = 1;
  pl.type_payload_count[content_type] = cnt;
  log_debug("init_payload_pool: type_payload_count for content_type %d = %d",
     content_type, pl.type_payload_count[content_type]); 
  log_debug("min_payload_size = %d", min_payload_size); 
  log_debug("max_payload_size = %d", max_payload_size); 
  log_debug("avg_payload_size = %f", (float)sum_payload_size/(float)(cnt == 0 ? 1 : cnt)); 
  return RCODE_OK;
}









rcode_t 
get_next_payload (payloads& pl, int content_type, char*& buf, size_t& size, size_t& cap)
{
  int r;

  log_debug("get_next_payload: content_type = %d, init_type_payload = %d, type_payload_count = %d",
      content_type, pl.init_type_payload[content_type], pl.type_payload_count[content_type]);


  if (content_type <= 0 ||
      content_type >= MAX_CONTENT_TYPE ||
      pl.init_type_payload[content_type] == 0 ||
      pl.type_payload_count[content_type] == 0)
    return RCODE_ERROR;

  r = rand() % pl.type_payload_count[content_type];
  log_debug("SERVER: picked payload with index %d", r);

  buf = pl.payloads[pl.type_payload[content_type][r]];
  size = pl.payload_hdrs[pl.type_payload[content_type][r]].length;
  cap = pl.type_payload_cap[content_type][r];
  return RCODE_OK;
}








rcode_t 
get_payload (payloads& pl, int content_type, int cap, char*& buf, size_t& size) {
  int r, i, cnt, found = 0, num_candidate = 0, first, best, current;

  log_debug("content_type = %d, init_type_payload = %d, type_payload_count = %d",
            content_type, pl.init_type_payload[content_type],
            pl.type_payload_count[content_type]);

  if (content_type <= 0 || content_type >= MAX_CONTENT_TYPE ||
      pl.init_type_payload[content_type] == 0 ||
      pl.type_payload_count[content_type] == 0)
    return RCODE_ERROR;


  cnt = pl.type_payload_count[content_type];
  r = rand() % cnt;
  best = r;
  first = r;

  i = -1;
  // we look at MAX_CANDIDATE_PAYLOADS payloads that have enough capacity
  // and select the best fit
  while (i < (cnt-1) && num_candidate < MAX_CANDIDATE_PAYLOADS) {
    i++;
    current = (r+i)%cnt;

    if (pl.type_payload_cap[content_type][current] < cap)
      continue;

    if (found) {
      if (pl.payload_hdrs[pl.type_payload[content_type][best]].length >
          pl.payload_hdrs[pl.type_payload[content_type][current]].length)
        best = current;
    } 
    else {
      first = current;
      best = current;
      found = 1;
    }
    num_candidate++;
  }

  if (found) {
    log_debug("first payload size=%d, best payload size=%d, num candidate=%d",
      pl.payload_hdrs[pl.type_payload[content_type][first]].length,
      pl.payload_hdrs[pl.type_payload[content_type][best]].length,
      num_candidate);
    buf = pl.payloads[pl.type_payload[content_type][best]];
    size = pl.payload_hdrs[pl.type_payload[content_type][best]].length;
    return RCODE_OK;
  } 

  return RCODE_ERROR;

}






