/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _JSUTIL_H
#define _JSUTIL_H

// jsSteg-specific defines
#define JS_DELIMITER 'Z'
// a JavaScript delimiter is used to signal the end of encoding
// to facilitate the decoding process
#define JS_DELIMITER_REPLACEMENT 'Y'
// JS_DELIMITER that exists in the JavaScript before the end of
// data encoding will be replaced by JS_DELIMITER_REPLACEMENT
#define JS_DELIMITER_SIZE 1

// #define JS_MIN_AVAIL_SIZE 2050
#define JS_MIN_AVAIL_SIZE 1026
// JS_MIN_AVAIL_SIZE should reflect the min number of data bytes
// a JavaScript may encapsulate

// flag to control whether to remove JavaScript comments
#define REMOVE_JS_COMMENT 1
// #define REMOVE_JS_COMMENT 0

// flag to control whether to perturb non-hex alphabet char in JS
#define PERTURB_JS 1
// #define PERTURB_JS 0

// flag to control whether to remove JavaScript comments embedded in HTML
#define REMOVE_HTML_JS_COMMENT 1
// #define REMOVE_HTML_JS_COMMENT 0

// flag to control whether to perturb non-hex alphabet char in JS embedded in HTML
#define PERTURB_HTML_JS 1
// #define PERTURB_HTML_JS 0

// control the prob for non-hex alphabet char (i.e., [g-z,G-Z])
// perturbation in JS
// e.g., 90 means that perturbation may occur 9 out of 10 times,
// and 50 means that we may replace a non-hex alphabet char
// half of the time 
#define PERTURB_JS_PROB 80

// minimum word length for perturb
#define PERTURB_JS_MIN_WORDLEN 3

// control whether to drop non-hex char with probability 1-PERTURB_JS_PROB/100
// #define PERTURB_JS_DROP_NONHEX 0
#define PERTURB_JS_DROP_NONHEX 1

#define JS_SCRIPT_START "<script type=\"text/javascript\">"
#define JS_SCRIPT_END "</script>"

size_t skip_JS_pattern(char *cp, int len);

rcode_t remove_js_comment (char *msg_start, size_t msg_len, char *tmp_buf, size_t tmp_buf_len, size_t& new_msg_len);

rcode_t perturb_JS (char *msg_start, size_t msg_len, char *tmp_buf, size_t tmp_buf_len, size_t& new_msg_len);

rcode_t remove_js_comment_in_HTML (char *msg_start, size_t msg_len, char *tmp_buf, size_t tmp_buf_len, size_t& new_msg_len);

rcode_t perturb_JS_in_HTML (char *msg_start, size_t msg_len, char *tmp_buf, size_t tmp_buf_len, size_t& new_msg_len);

unsigned int capacity_JS (char* buf, int len, int mode);

int isalnum_ (char c);

int offset2Alnum_ (char *p, int range);

int offset2Hex (char *p, int range, int isLastCharHex);

int count_GIM (char *word, int wlen);

int  offset2Non_alnum_ (char *p, int range);

int  offset2Non_num (char *p, int range);


#endif
