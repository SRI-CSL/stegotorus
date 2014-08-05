/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _JPEGSTEG_H
#define _JPEGSTEG_H

#include "http.h"
#include "jel_knobs.h"

#define JPEG_CONTENT_TYPE   "image/jpeg"
#define JPEG_SIZE_CEILING   4096

transmit_t http_server_JPEG_transmit (http_steg_t * s, struct evbuffer *source);

transmit_t http_client_JPEG_post_transmit (http_steg_t *s, struct evbuffer *source, conn_t *conn);

recv_t http_client_JPEG_receive(http_steg_t * s, struct evbuffer *dest, char* headers, int headers_length, char* response, int response_length);

recv_t http_server_JPEG_post_receive(http_steg_t * s, struct evbuffer *dest, char* headers, int headers_length, char* request, int request_length);

void set_jel_preferences_to_default();

void set_jel_preferences(jel_knobs_t &knobs_in);

#endif
