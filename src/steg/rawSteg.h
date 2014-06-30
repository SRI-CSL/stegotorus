/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _RAWSTEG_H
#define _RAWSTEG_H

#include "http.h"

#define RAW_CONTENT_TYPE   "application/octet-stream"
#define RAW_SIZE_CEILING   8192

//4096

transmit_t http_server_RAW_transmit (http_steg_t * s, struct evbuffer *source);

transmit_t http_client_RAW_post_transmit (http_steg_t *s, struct evbuffer *source, conn_t *conn);

recv_t http_client_RAW_receive (http_steg_t * s, struct evbuffer *dest, char* headers, size_t headers_length, char* response, size_t response_length);

recv_t http_server_RAW_post_receive (http_steg_t * s, struct evbuffer *dest, char* headers, size_t headers_length, char* request, size_t request_length);


#endif
