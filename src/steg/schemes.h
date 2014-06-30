/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _SCHEMES_H
#define _SCHEMES_H

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>


#include "payloads.h"

/* very useful if something is going wrong; use just one circuit a flick this puppy on */
#define SCHEMES_DEBUG  0

/* data statistics at the end of each send */
#define SCHEMES_PROFILING 0

enum STEG_TRANSPORT_SCHEMES {
  COOKIE_TRANSMIT  = 0,
  URI_TRANSMIT,
  JSON_POST,
  PDF_POST,
  JPEG_POST,
  RAW_POST,
  SWF_GET,
  PDF_GET,
  JS_GET,
  HTML_GET,
  JSON_GET,
  JPEG_GET,
  RAW_GET,
  STEG_TRANSPORT_SCHEMES_MAX
};

int schemes_init(void);

int schemes_get_transmit_scheme(size_t size);

const char* schemes_to_string(int scheme);

int schemes_string_to_scheme(const char* scheme_name);

bool schemes_set_scheme(int scheme, int value);

bool schemes_is_enabled(int content_type);

bool schemes_is_usable(int content_type);

void schemes_success(int content_type);

void schemes_failure(int content_type);

void schemes_clientside_init(payloads& payloads, const char* imagedir, const char* pdfdir);

void schemes_serverside_init(payloads& payloads, const char* imagedir, const char* pdfdir);

int schemes_clientside_transmit_room(payloads& payloads, size_t pref, size_t& lo, size_t& hi);

int schemes_serverside_transmit_room(payloads& payloads, int content_type, size_t pref, size_t& lo, size_t& hi);

rcode_t schemes_gen_uri_field(char* uri, size_t uri_sz, char* data, size_t& datalen);

int schemes_gen_post_request_path(payloads& p, char** uri);

void schemes_dump(FILE*);

#endif




