/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _MRAWSTEG_H
#define _MRAWSTEG_H

#include "stream.h"

//mixed-replace stream raw as a warm up exercise for motion jpeg or MJPEG steg.
//See: multipart/x-mixed-replace

#define MRAW_CONTENT_TYPE         "multipart/x-mixed-replace"
#define MRAW_PART_CONTENT_TYPE    "application/octet-stream"
#define MRAW_SIZE_CEILING          2048
#define MRAW_MAX_PART_HEADERS_SIZE 1024

transmit_t stream_server_MRAW_transmit (stream_steg_t * s, struct evbuffer *dest, struct evbuffer *source);

transmit_t stream_client_MRAW_transmit (stream_steg_t * s, struct evbuffer *dest, struct evbuffer *source);

recv_t stream_client_MRAW_receive (stream_steg_t * s, struct evbuffer *dest, struct evbuffer *source);

recv_t stream_server_MRAW_receive (stream_steg_t * s, struct evbuffer *dest, struct evbuffer *source);

#endif

