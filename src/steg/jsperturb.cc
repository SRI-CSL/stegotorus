/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */


#include <ctype.h>
#include "util.h"
#include "rng.h"
#include "payloads.h"
#include "jsutil.h"
#include "strncasestr.h"
#include "oshacks.h"

/*
 * for each non-hex alphanumeric char, we probabilistically change it to another non-hex
 * alphanumeric char with probability PERTURB_JS_PROB/100;
 * otherwise, we drop this non-hex, if PERTURB_JS_DROP_NONHEX, to increase length variation
 *
 * for each hex char, we probabilistically change it to another hex char with prob
 * PERTURB_JS_PROB/100
 *
 * input:
 * word: pointer to the input word
 * wlen: length of the input word
 *
 * output:
 * function returns the length of the resulting word
 * buf: pointer to the output buffer
 * buflen: size of the output buffer
 *
 */


rcode_t 
perturb_word (char *word, size_t wlen, char* buf, size_t buflen, size_t& new_wlen) 
{
   char *cp = NULL, *tp = NULL;
   int  prob = 0;
   char tmpbuf[2048]; /* our server.out largest word is 1444 bytes */
   char keypad[] = "ghijklmnopqrstuvwxyz_GHIJKLMNOPQRSTUVWXY";
   int  keypadlen = strlen(keypad);
   char hexpad[] = "abcdef0123456789ABCDEF0123456789";
   int  hexpadlen = strlen(hexpad);

   new_wlen = wlen;

   if (PERTURB_JS_PROB < 0 || PERTURB_JS_PROB > 100) {
     log_warn("incorrect PERTURB_JS_PROB specified (%d); it must be in [0,100]", PERTURB_JS_PROB);
     log_warn("setting PERTURB_JS_PROB to 50");
     prob = 50;
   } 
   else {
     prob = PERTURB_JS_PROB;
   }

   if (wlen <= 0 || buflen <= wlen)
     goto err;

   cp = word;
   
   // don't replace short words (those with < PERTURB_JS_MIN_WORDLEN char)
   if (wlen < PERTURB_JS_MIN_WORDLEN) {
     if (memncpy (buf, buflen, word, wlen) != RCODE_OK) {
       log_warn("memncpy failed");
       goto err;
     }
     goto done;
   }

   // skipping modifiers of JS regular exp: 
   // don't perturb a word if it's of length < 4 and contains only i, g, and m
   if ((wlen < 4) && ((size_t)count_GIM(word, wlen) == wlen)) {
     if (memncpy (buf, buflen, word, wlen) != RCODE_OK) {
       log_warn("memncpy failed");
       goto err;
     }
     goto done;
   }

   if (isdigit(*cp) && wlen > 1) {
     // if the first char is a digit, replace it with a random char in keypad
     // so that we don't introduce a syntactically invalid word
     *cp = keypad[randomg()%keypadlen]; 
   }

   if (wlen > 1024) {
     log_debug("word length (%" PriSize_t ") greater than buffer size (%d)", wlen, 1024);
     // no change
     
     if (memncpy (buf, buflen, word, wlen) != RCODE_OK) {
       log_warn("memncpy failed");
       goto err;
     }

     goto done;
   }

   tp = tmpbuf;

   while (cp < word+wlen) {
     if (isalnum(*cp) && !isxdigit(*cp)) {
       // we flip a coin to decide whether to replace *cp
       if ((randomg()%100) < prob) {
	 // pick a random char from keypad
	 *tp++ = keypad[randomg()%keypadlen]; 
       } 
       else {
	 // if PERTURB_JS_DROP_NONHEX and this isn't the first char of a word,
	 // we skip this non-hex char
	 if (! PERTURB_JS_DROP_NONHEX || cp == word) {
	   *tp++ = *cp; 
	 }
       }
     } else if (isxdigit(*cp)) {
       if ((randomg()%100) < prob && cp != word) {
	 // don't replace this char if it's the first char of a word
	 *tp++ = hexpad[randomg()%hexpadlen]; 
       } else {
	 *tp++ = *cp; 
       }
     } else if (*cp == '.') {
       *tp++ = keypad[randomg()%keypadlen];
     } else {
       *tp++ = *cp; 
     }
     cp++;
   }
   *tp = 0;
   
   // check that the word in tmpbuf is not a JS keyword
   if (tp != tmpbuf && skip_JS_pattern(tmpbuf, tp-tmpbuf+1) == 0) {
     if (memncpy (buf, buflen, tmpbuf, tp-tmpbuf) != RCODE_OK) {
       log_warn("memncpy failed");
       goto err;
     }
     new_wlen = tp-tmpbuf;
     goto done;
   } 
   
   if (memncpy (buf, buflen, word, wlen) != RCODE_OK) {
     log_warn("memncpy failed");
     goto err;
   }


 done:
  return RCODE_OK;

 err:
  log_warn("perturb_word failed");
  return RCODE_ERROR;
}


/*
 * transform a java_script by replacing alphabet characters that are 
 * not used for encoding data (i.e., [g-z,g-z] for the hex-encoding scheme)
 * with random characters of the same set.
 * to preserve the syntax validity of the JS, we only choose words that are
 * not JS keywords for the transformation.
 *
 */

rcode_t 
perturb_JS2 (char *js_start, int js_len, char *buf_start, int buf_len, size_t& new_js_len) 
{

  char *cp = js_start, *bp = buf_start, *js_end = NULL, *buf_end = NULL;
  size_t k = 0;
  int is_num = 0;
  size_t i = 0, j = 0;
  rcode_t rval;

  new_js_len = js_len;
  js_end = js_start + js_len;
  buf_end = buf_start + buf_len;

  while (cp < js_end) {

    // find the beginning of a word that starts with an alphanumeric or underscore
    rval = offset2Alnum_(cp, js_end-cp, i);

    // no such word found
    if (rval == RCODE_NOT_FOUND) {
      if (buf_end-bp <= js_end-cp) {
	log_debug ("output buffer too small");
	goto err;
      }

      // copy the rest of JS and break
      if (memncpy (bp, buf_end-bp, cp, js_end-cp) != RCODE_OK) {
	log_debug ("memncpy failed");
	goto err;
      }

      bp = bp + (js_end-cp); 
      cp = js_end; 
      goto done;
    }

    // starting from cp, copy the next i char from the input buf to the output buf
    if (i > 0) {
      if ((size_t) (buf_end - bp) < i) {
        log_debug ("outbuf buffer too small");
        goto err;
      }

      if (memncpy (bp, buf_end-bp, cp, i) != RCODE_OK) {
        log_debug("memncpy failed");
        goto err;
      }
      cp += i; 
      bp += i;
    }

    // find the end of the word, i.e., the first non-alphanumeric-or-underscore char
    // starting from cp+1
    if (cp+1 > js_end) {
      *bp = *cp; cp++; bp++;
      // end of JS detected; this shouldn't happen 
      log_debug("cannot find end of word");
      goto done;
    }

    is_num = 0;

    if (isdigit(*cp)) {

      // handling the case in which a number starts with a dot
      if (cp > js_start && *(cp-1) == '.') {
	*(bp-1) = '_';
      }

      is_num = 1;
      rval = offset2Non_num(cp, js_end-cp, j);
    } 
    else {
      rval = offset2Non_alnum_(cp, js_end-cp, j);
    }

    if (rval == RCODE_NOT_FOUND) {
      if (memncpy (bp, buf_end-bp, cp, js_end-cp) != RCODE_OK) {
        log_debug("memncpy failed");
        goto err;
      }

      bp = bp + (js_end-cp); 
      cp = js_end; 
      goto done;
    }


    // before we perturb the word, check to see if it's a JS keyword
    if (!is_num) {
      k = skip_JS_pattern(cp, j+1);
      if (k > 0) {
	if ((bp + k) > buf_end) {
	  log_debug ("output buffer too small");
	  goto err;
	} 
	
	if (memncpy (bp, buf_end-bp, cp, k) != RCODE_OK) {
	  log_debug("memncpy failed");
	  goto err;
	}
	goto advance;
      }
    }


    // perturb word, write the result in buf, and increment cp and bp
    if (perturb_word(cp, j, bp, buf_end-bp, k) != RCODE_OK) {
      log_warn("perturb_word failed!");
      goto err;
    }

  advance:
    cp += k; 
    bp += k;
  } // while

 done:
  new_js_len = bp - buf_start;
  return RCODE_OK;
  
 err:
  log_warn("perturb_JS2 failed");
  return RCODE_ERROR;
}


/*
 * transform HTTP response with JS payload using perturb_JS2  
 */
rcode_t 
perturb_JS (char *msg_start, size_t msg_len, char *tmp_buf, size_t tmp_buf_len, size_t& new_msg_len) 
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

  if (perturb_JS2(msg_start+hdr_len, body_len, tmp_buf, tmp_buf_len, new_body_len) != RCODE_OK) {
    log_warn("perturb_JS: perturb_JS2 failed");
    goto err;
  }

  if (new_body_len <= body_len) {
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
 * transform the JS embedded in HTML documents of HTTP responses using perturb_JS2
 */
rcode_t
perturb_JS_in_HTML (char *msg_start, size_t msg_len, char *tmp_buf, size_t tmp_buf_len, size_t& new_msg_len) 
{

  // assumptions:
  // msg_start points to an HTTP msg body containing a java_script
  // char array pointed to by msg_start is null-terminated

  char *hdr_end = NULL, *bp = NULL, *tp = NULL, *js_start = NULL, *js_end = NULL;
  size_t hdr_len = 0, body_len = 0, new_body_len = 0, js_len = 0;

  new_msg_len = msg_len;

  if (tmp_buf_len < msg_len) {
    log_debug("buffer too small");
    goto err;
  }

  hdr_end = strnstr(msg_start, "\r\n\r\n", msg_len);
  if (hdr_end == NULL) {
    log_debug("unable to find end of header in the HTTP template");
    goto err;
  }

  hdr_len = hdr_end+4-msg_start;

  if (msg_len < hdr_len) {
    log_debug("problem computing the len of HTTP msg body");
    goto err;
  }

  body_len = msg_len - hdr_len;
  bp = hdr_end+4;
  tp = tmp_buf;


  while (bp < (msg_start+msg_len)) {    
    js_start = strnstr(bp, JS_SCRIPT_START, msg_len-(bp-msg_start)); 

    if (js_start == NULL) 
      break;
    
    // copy non-js text between bp and (js_start+31) to tp
    if (memncpy (tp, (tmp_buf+tmp_buf_len)-tp, bp, js_start-bp + sizeof(JS_SCRIPT_START) - 1) != RCODE_OK) {
      goto err;
    }

    tp += (js_start - bp + sizeof(JS_SCRIPT_START) - 1);
    bp = js_start + sizeof(JS_SCRIPT_START) - 1;    
    js_end = strnstr(bp, JS_SCRIPT_END, msg_len-(bp-msg_start));

    if (js_end == NULL) 
      break;
    
    if (perturb_JS2(js_start + sizeof(JS_SCRIPT_START) - 1, js_end-bp, tp, tmp_buf_len-(tp-tmp_buf), js_len) != RCODE_OK) {
      log_debug("perturb_JS_in_HTML: perturb_JS2 failed");
      goto err;
    }

    tp += js_len;
    
    if (memncpy (tp, (tmp_buf+tmp_buf_len)-tp, JS_SCRIPT_END, 9) != RCODE_OK) {
      goto err;
    }
    
    tp += 9;
    bp = js_end+9; 
  }
  
  // copy the rest of the body to tmp_buf
  if (bp < (msg_start+msg_len)) {

    if (memncpy (tp, (tmp_buf+tmp_buf_len)-tp, bp, msg_start+msg_len-bp) != RCODE_OK) {
      goto err;
    }
    
    tp += msg_start+msg_len-bp;
  }


  new_body_len = tp-tmp_buf;

  if (new_body_len <= body_len) {
    new_msg_len = hdr_len + new_body_len;

    // inplace modification of pl.payloads[r]
    if (memncpy (msg_start+hdr_len, (msg_len-hdr_len), tmp_buf, new_body_len) != RCODE_OK) {
      goto err;
    }

    msg_start[new_msg_len] = 0;
  }

  return RCODE_OK;

 err:
  log_warn("error in perturb_JS_in_HTML");
  return RCODE_ERROR;
}

