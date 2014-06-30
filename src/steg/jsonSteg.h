/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _JSONSTEG_H
#define _JSONSTEG_H

#include "http.h"


#define JSON_CONTENT_TYPE  "application/json"
#define JSON_SIZE_CEILING   4096




//implemented but turned off while in active development
//#define JSON_ZIPPING       1

transmit_t http_server_JSON_transmit (http_steg_t * s, struct evbuffer *source);

transmit_t http_client_JSON_post_transmit (http_steg_t *s, struct evbuffer *source, conn_t *conn);

recv_t http_client_JSON_receive (http_steg_t *s, struct evbuffer *dest, char* headers, size_t headers_length, char* request, size_t request_length);

recv_t http_server_JSON_post_receive (http_steg_t *s, struct evbuffer *dest, char* headers, size_t headers_length, char* request, size_t request_length);

#endif
