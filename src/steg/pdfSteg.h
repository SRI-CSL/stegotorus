/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _PDFSTEG_H
#define _PDFSTEG_H

#include "http.h"

#define PDF_CONTENT_TYPE   "application/pdf"
#define PDF_SIZE_CEILING   20480

#define PDF_DELIMITER    '?'
#define PDF_DELIMITER2   '.'

#define STREAM_BEGIN       "stream"
#define STREAM_BEGIN_SIZE  6
#define STREAM_END         "endstream"
#define STREAM_END_SIZE    9


// These are the public interface.

recv_t http_client_PDF_receive  (http_steg_t * s, struct evbuffer *dest, char* headers, size_t headers_length, char* response, size_t response_length);

transmit_t http_server_PDF_transmit (http_steg_t * s, struct evbuffer *source);

recv_t http_server_PDF_post_receive (http_steg_t * s, struct evbuffer *dest, char* headers, size_t headers_length, char* request, size_t request_length);

transmit_t http_client_PDF_post_transmit (http_steg_t * s, struct evbuffer *source, conn_t *conn);


// These are exposed only for the sake of unit tests.
rcode_t pdf_wrap (const char *data, size_t dlen, const char *pdf_template, size_t plen,
                  char *outbuf, size_t outbufsize, size_t& bytes_wrriten);

rcode_t pdf_unwrap (const char *data, size_t dlen, char *outbuf, size_t outbufsize, size_t& bytes_written);

#endif
