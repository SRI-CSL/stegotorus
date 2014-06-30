/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */


#include <ctype.h>
#include "util.h"
#include "payloads.h"
#include "jsutil.h"
#include "strncasestr.h"



rcode_t
skip_multiline_comment(char*& cp, char* js_end) 
{

  bool end_of_comment = false;

  cp = cp+2;

  while (cp < js_end) {
    if (*cp != '*') {
      cp++;
      continue;
    }
    if ((cp+1) == js_end) {
      log_warn("malformed JS [1]: missing end of multi-line comment");
      return RCODE_ERROR;
    }

    if (*(cp+1) == '/') {
      // end of multi-line comment detected
      cp = cp+2;
      end_of_comment = true;
      break;
    } 
    cp++;
  }

  if (!end_of_comment) {
    log_warn("malformed JS [2]: missing end of multi-line comment");
    return RCODE_ERROR;
  }


  return RCODE_OK;
}


void 
handle_double_quoted_strings(char*& cp, char*& tp, char* js_end, bool& escaped, size_t& new_js_len) 
{

  while (cp < js_end) {
    *tp++ = *cp++;
    new_js_len++;

    if (*cp == '\\' && !escaped) {
      escaped = true;
    } 
    else if (*cp == '"' && !escaped) {
      // end of double-quoted strings
      *tp++ = *cp++;
      new_js_len++;
      break;
    } 
    else {
      escaped = false;
    }
  }
}
  





void 
handle_single_quoted_strings(char*& cp, char*& tp, char* js_end, bool& escaped, size_t& new_js_len) 
{
  while (cp < js_end) {
    *tp++ = *cp++;
    new_js_len++;
    
    if (*cp == '\\' && !escaped) {
      escaped = true;
    } 
    else if (*cp == '\'' && !escaped) {
      // end of single-quoted strings
      *tp++ = *cp++;
      new_js_len++;
      break;
    } 
    else {
      escaped = false;
    }
  }
}



/*
 * remove_js_comment2 removes JS comments from the input JS specified by js_start
 * with length js_len, and
 * puts the resulting JS (without comments) in the output buffer specified by
 * buf_start of size buf_len
 *
 * remove_js_comment2 puts the length of the resulting JS in new_js_len, if success
 */

rcode_t 
remove_js_comment2 (char *js_start, int js_len, char *buf_start, int buf_len, size_t& new_js_len) 
{

  // two formats for JS comments:
  // multi-line comments, which start with /_* and end with *_/,
  // with the underscores removed
  // single-line comments, which start with /_/, with the underscore removed,
  // until the end of lines

  char *cp = js_start;
  char* js_end = NULL, *tp = NULL;  
  bool escaped = false;

  new_js_len = js_len;

  if (buf_len < js_len) {
    log_warn("output buffer too small");
    goto err;
  }

  tp = buf_start;
  js_end = js_start+js_len;

  while (cp < js_end) {
    if (*cp == '\'' && !escaped) {  // single-quoted strings
      handle_single_quoted_strings(cp, tp, js_end, escaped, new_js_len);
      continue;
    } 
    else if (*cp == '"' && !escaped) {  // double-quoted strings
      handle_double_quoted_strings(cp, tp, js_end, escaped, new_js_len);
      continue;
    } 
    else if (*cp == '/' && !escaped) {
      // possible start of JS comments
      if ((cp+1) == js_end) {
        // malformed JS
        log_warn("malformed JS?: ending with a slash");
        goto err;
      }

      if (*(cp+1) == '*') {
	// start of a multi-line comment, remove everything until end of multi-line comment
	if (skip_multiline_comment(cp, js_end) != RCODE_OK)
	  goto err;
	continue;
      } 
     
      if (*(cp+1) == '/') {
        cp = cp + 2;

	// start of a single-line comment, remove everything until end of line
        while (cp < js_end) {
          if (*cp == '\r' || *cp == '\n') {
            cp++;
            break;
          }
          cp++;
        }
	continue;
      } 
    }
    else {  // *cp <> '/' and not in strings
      if (*cp == '\\' && !escaped) {
	escaped = true;
      } 
      else {
        escaped = false;
      }
    }

    *tp++ = *cp;
    new_js_len++;
    cp++;
  }
  
  return RCODE_OK;

 err:
  return RCODE_ERROR;
}



/*
 * remove_js_comment takes an HTTP response with a JS in the payload (specified
 * by msg_start of length msg_len), removes JS comments in the payload, and puts
 * the result in the output buffer specified by tmp_buf of size tmp_buf_len
 *
 * remove_js_comment puts the length of the resulting payload in new_msg_len, if success
 */

rcode_t 
remove_js_comment (char *msg_start, size_t msg_len, char *tmp_buf, size_t tmp_buf_len, size_t& new_msg_len) 
{

  // assumptions: 
  // msg_start points to an HTTP msg body containing a java_script
  // char array pointed to by msg_start is null-terminated

  char *hdr_end = NULL;
  size_t hdr_len = 0, body_len = 0, new_body_len = 0;

  new_msg_len = msg_len;

  if (tmp_buf_len < msg_len) {
    log_warn("buffer too small");
    goto err;
  }

  hdr_end = strnstr(msg_start, "\r\n\r\n", msg_len);

  if (hdr_end == NULL) {
    log_warn("unable to find end of header in the HTTP template");
    goto err;
  }
  hdr_len = hdr_end+4-msg_start;

  if (msg_len < hdr_len) {
    log_warn("problem computing the len of HTTP msg body");
    goto err;
  }

  body_len = msg_len - hdr_len;

  if (remove_js_comment2(msg_start+hdr_len, body_len, tmp_buf, tmp_buf_len, new_body_len) != RCODE_OK) {
    log_warn("remove_js_comment2 failed");
    goto err;
  }

  if (new_body_len < body_len) {
    new_msg_len = hdr_len + new_body_len;
    // inplace modification of pl.payloads[r]

    if (memncpy (msg_start+hdr_len, (msg_len-hdr_len), tmp_buf, new_body_len) != RCODE_OK) {
      log_warn("memncpy failed");
      goto err;
    }

    msg_start[new_msg_len] = 0;
  }

  return RCODE_OK;

 err:
  return RCODE_ERROR;
}


/*
 * remove_js_comment_in_HTML takes an HTTP response containing an HTML document (specified
 * by msg_start with length msg_len), removes its JS comments for the JS embedded in it,
 * and puts the resulting HTML document in the output buffer specified by tmp_buf of
 * size tmp_buf_len
 *
 * remove_js_comment_in_HTML returns the size of the resulting payload, if success;
 * otherwise, it returns -1
 */

rcode_t 
remove_js_comment_in_HTML (char *msg_start, size_t msg_len, char *tmp_buf, size_t tmp_buf_len, size_t& new_msg_len) 
{

  // assumptions:
  // msg_start points to an HTTP msg body containing a java_script
  // char array pointed to by msg_start is null-terminated

  char *hdr_end, *bp, *tp, *js_start, *js_end;
  size_t hdr_len, body_len, new_body_len, js_len;

  new_msg_len = msg_len;

  if (tmp_buf_len < msg_len) {
    log_warn("buffer too small");
    goto err;
  }

  hdr_end = strnstr(msg_start, "\r\n\r\n", msg_len);

  if (hdr_end == NULL) {
    log_warn("unable to find end of header in the HTTP template");
    goto err;
  }
  hdr_len = hdr_end+4-msg_start;

  if (msg_len < hdr_len) {
    log_warn("problem computing the len of HTTP msg body");
    goto err;
  }
  body_len = msg_len - hdr_len;

  bp = hdr_end+4;
  tp = tmp_buf;

  while (bp < (msg_start+msg_len)) {

       js_start = strnstr(bp, JS_SCRIPT_START, msg_len-(bp-msg_start)); 
       if (js_start == NULL) break;

       // copy non-js text between bp and (js_start+31) to tp

       if (memncpy (tp, (tmp_buf+tmp_buf_len)-tp, bp, js_start-bp+31) != RCODE_OK) {
         log_debug("memncpy failed");
         goto err;
       }

       tp += (js_start - bp + 31);
       bp = js_start+31;

       js_end = strnstr(bp, JS_SCRIPT_END, msg_len-(bp-msg_start));
       if (js_end == NULL) break;

       if (remove_js_comment2(js_start+31, js_end-bp, tp, tmp_buf_len-(tp-tmp_buf), js_len) != RCODE_OK) {
         log_warn("remove_js_comment_in_HTML: remove_js_comment2 failed");
         goto err;
       }

       tp += js_len;

       if (memncpy (tp, (tmp_buf+tmp_buf_len)-tp, JS_SCRIPT_END, 9) != RCODE_OK) {
         log_warn("memncpy failed");
         goto err;
       }

       tp += 9;
       bp = js_end+9; 
  }

  // copy the rest of the body to tmp_buf
  if (bp < (msg_start+msg_len)) {

    if (memncpy (tp, (tmp_buf+tmp_buf_len)-tp, bp, msg_start+msg_len-bp) != RCODE_OK) {
      log_warn("memncpy failed");
      goto err;
    }
    
    tp += msg_start+msg_len-bp;
  }

  new_body_len = tp-tmp_buf;

  if (new_body_len < body_len) {
    new_msg_len = hdr_len + new_body_len;
    // inplace modification of pl.payloads[r]

    if (memncpy (msg_start+hdr_len, (msg_len-hdr_len), tmp_buf, new_body_len) != RCODE_OK) {
      log_warn("memncpy failed");
      goto err;
    }

    msg_start[new_msg_len] = 0;
  }

  return RCODE_OK;

 err:
  return RCODE_ERROR;
}

