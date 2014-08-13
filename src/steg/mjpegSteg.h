/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _MJPEGSTEG_H
#define _MJPEGSTEG_H

#include "stream.h"

/*
mixed-replace stream of jpegs.
See: multipart/x-mixed-replace

http://tools.ietf.org/html/rfc2046#section-5.1.1

"GET /mjpg/video.mjpg HTTP/1.1\r\nUser-Agent: curl/7.33.0\r\nHost: lioncam1.lmu.edu\r\nAccept:" star slash star
\r\n\r\n

HTTP/1.0 200 OK\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nExpires: Thu, 01 Dec 1994 16:00:00 GMT\r\nConnection: close\r\nContent-Type: multipart/x-mixed-replace; boundary=myboundary
\r\n\r\n
--myboundary\r\n
Content-Type: image/jpeg\r\n
Content-Length: X0\r\n
\r\n
[X0 raw bytes]
--myboundary\r\n
Content-Type: image/jpeg\r\n
Content-Length: X1\r\n
\r\n
[X1 raw bytes]
.
.
.
*/


#define MJPEG_CONTENT_TYPE         "multipart/x-mixed-replace"
#define MJPEG_PART_CONTENT_TYPE    "application/octet-stream"
#define MJPEG_SIZE_CEILING          2048
#define MJPEG_MAX_PART_HEADERS_SIZE 1024

transmit_t stream_server_MJPEG_transmit (stream_steg_t * s, struct evbuffer *dest, struct evbuffer *source);

transmit_t stream_client_MJPEG_transmit (stream_steg_t * s, struct evbuffer *dest, struct evbuffer *source);

recv_t stream_client_MJPEG_receive (stream_steg_t * s, struct evbuffer *dest, struct evbuffer *source);

recv_t stream_server_MJPEG_receive (stream_steg_t * s, struct evbuffer *dest, struct evbuffer *source);

#endif

