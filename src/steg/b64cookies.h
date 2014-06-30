/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _B64_COOKIES_H
#define _B64_COOKIES_H

#include "strncasestr.h"

rcode_t unwrap_b64_cookies(char *outbuf, size_t outbuflen, const char *inbuf, size_t inlen, size_t& bytes_written);
rcode_t gen_b64_cookies(char *outbuf, size_t outbuflen, const char *inbuf, size_t inlen, size_t& bytes_written);

#endif
