/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _JSSTEG_H
#define _JSSTEG_H

#include "http.h"

#define JAVASCRIPT_CONTENT_TYPE       "application/x-javascript"
#define HTML_JAVASCRIPT_CONTENT_TYPE  "text/html"




transmit_t http_server_JS_transmit (http_steg_t * s, struct evbuffer *source, unsigned int content_type);
recv_t http_client_JS_receive (http_steg_t * s, struct evbuffer *dest, char* headers, size_t headers_length, char* response, size_t response_length);


#endif
