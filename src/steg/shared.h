/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _SHARED_H
#define _SHARED_H

#include <stdio.h>
#include "types.h"
#include "protocol.h"


/* debugging related */
void evbuffer_dump(struct evbuffer *buf, FILE *out);
void buf_dump(char* buf, size_t len, FILE *out);


/* random other */
size_t clamp(size_t val, size_t lo, size_t hi);
int lookup_peer_name_from_ip(const char* p_ip, char* p_name, int p_name_size);


/* string related */

bool is_hex_string(char *str, size_t str_length); 
rcode_t source2hex(struct evbuffer *source, size_t source_length, char **datap, size_t& data_length);
recv_t hex2dest(struct evbuffer *dest,  size_t data_length, char *data);
rcode_t source2raw(struct evbuffer *source, size_t source_length, uchar **datap, size_t& data_length);
recv_t raw2dest(struct evbuffer *dest,  size_t data_length, uchar *data);


/*
  sets the headers and headers length and returns RECV_GOOD upon success,
  RECV_INCOMPLETE if they are NOT all in yet, or RECV_BAD on failure;
  allocs and copies a NULL terminated copy of the headers to headersp!
  leaves everything on the source evbuffer
*/


recv_t peek_headers(struct evbuffer *source, char **headersp, size_t& headers_length);
rcode_t peek_content(struct evbuffer *source, size_t headers_length, char *headers, char **responsep, size_t& response_length);



// 0 on success , -1 on failure: guesses a size -- compressed_datap receives the newly allocated buffer 
int compressor(char* data,  size_t datalen, char** compressed_datap, size_t *compressed_datalenp);

// 0 on success , -1 on failure: guesses a size, then reallocs if too small -- decompressed_datap receives the newly allocated buffer  
int decompressor(char* data,  size_t datalen, char** decompressed_datap, size_t *decompressed_datalenp);

void profile_data(const char* scheme, size_t headers_length, size_t body_length, size_t source_length);


#endif
