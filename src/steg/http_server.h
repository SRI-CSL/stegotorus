/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _HTTP_SERVER_H
#define _HTTP_SERVER_H

#include "http.h"


transmit_t http_server_transmit (http_steg_t * s, struct evbuffer *source);

recv_t http_server_receive(http_steg_t *s, struct evbuffer *dest, struct evbuffer* source, char *headers, size_t headers_length);

#endif

