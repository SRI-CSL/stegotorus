/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _HEADERS_H
#define _HEADERS_H

#include <stdio.h>
#include "stegerrors.h"

/* iam says:  trying to add some logical structure; this stuff deals with the HTTP headers */

/*
 * if the headers are longer than this we are going to assume we are under a 
 * denial of service attack, currently  16K.
 */
#define DOS_ALERT_SIZE  16384

/* hoping this one can go away */
#define MAX_HEADERS_SIZE 1536

#define MIN_COOKIE_SIZE 24
#define MAX_COOKIE_SIZE 1024

typedef enum  methods {
  HTTP_GET = 0,
  HTTP_HEAD,
  HTTP_POST,
  HTTP_UNKNOWN
} http_method_t;


#define HTTP_HEADERS_END               "\r\n\r\n"
#define HTTP_HEADERS_EOL               "\r\n"
#define HTTP_HEADERS_CONTENT_LENGTH    "content-length: "
#define HTTP_HEADERS_ACCEPT            "accept: "
#define HTTP_HEADERS_ACCEPT_ENCODING   "accept-encoding: "
#define HTTP_HEADERS_CONTENT_ENCODING  "content-encoding: "



/* 
 *  specifying the type of contents as an input argument
 *  for has_eligible_HTTP_content()
 */

typedef enum HTTP_CONTENT_TYPES {
  HTTP_CONTENT_NONE        = 0,
  HTTP_CONTENT_JAVASCRIPT,
  HTTP_CONTENT_PDF,
  HTTP_CONTENT_SWF,
  HTTP_CONTENT_ENCRYPTEDZIP,
  HTTP_CONTENT_HTML,
  HTTP_CONTENT_JSON,
  HTTP_CONTENT_JPEG,
  HTTP_CONTENT_RAW,
  HTTP_CONTENT_TYPES_MAX
} http_content_t;



/*
 * Fake hostname for Host: headers
 * Typically gets replaced by Jumpbox or ignored by StegoTorus Server
 */
#define HTTP_FAKE_HOST "localhost"

const char* http_content_type_to_string(http_content_t content_type);

int get_http_status_code(char* headers, size_t headers_length);
http_method_t get_method(char* headers, size_t headers_length);
rcode_t get_cookie(char* headers, size_t headers_length, char** cookiep, size_t& cookie_length);
rcode_t get_content_length(char* headers, size_t headers_length, size_t& content_length);
rcode_t get_accept(char* headers, size_t headers_length, char** acceptp, size_t& vlength);
rcode_t get_accept_encoding(char* headers, size_t headers_length, char** encodingp, size_t& vlength);
rcode_t get_content_encoding(char* headers, size_t headers_length, char** encodingp, size_t& vlength);

http_content_t find_content_type(char* headers, size_t headers_length);

bool is_gzip_encoded(char* headers, size_t headers_length);
bool will_accept_gzip(char* headers, size_t headers_length);
int yearns4gzip(char* headers, size_t headers_length);

rcode_t decode_cookie(const char* cookie, size_t cookie_length, char*out_buffer, size_t& sofar);
rcode_t encode_cookie(const char* data, size_t data_length, char**cookie, size_t& cookie_length);
rcode_t decode_uri(char* headers, size_t headers_length, char* out_buffer, size_t outbuf_len, 
		   size_t& bytes_written);


#endif
