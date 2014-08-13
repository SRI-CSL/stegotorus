/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _MHEXSTEG_H
#define _MHEXSTEG_H

#include "stream.h"

//mixed-replace stream of hex as a warm up exercise for motion jpeg or MJPEG steg.
//See: multipart/x-mixed-replace

#define MHEX_CONTENT_TYPE         "multipart/x-mixed-replace"
#define MHEX_PART_CONTENT_TYPE    "application/octet-stream"
#define MHEX_SIZE_CEILING          2048
#define MHEX_MAX_PART_HEADERS_SIZE 1024

transmit_t stream_server_MHEX_transmit (stream_steg_t * s, struct evbuffer *dest, struct evbuffer *source);

transmit_t stream_client_MHEX_transmit (stream_steg_t * s, struct evbuffer *dest, struct evbuffer *source);

recv_t stream_client_MHEX_receive (stream_steg_t * s, struct evbuffer *dest, struct evbuffer *source);

recv_t stream_server_MHEX_receive (stream_steg_t * s, struct evbuffer *dest, struct evbuffer *source);

#endif

