/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _SWFSTEG_H
#define _SWFSTEG_H

#include "http.h"

struct payloads;

#define SWF_SAVE_HEADER_LEN 1500
#define SWF_SAVE_FOOTER_LEN 1500

rcode_t
swf_wrap(payloads& pl, char* inbuf, size_t in_len, char*& outbuf, size_t out_sz);

rcode_t
swf_unwrap(char* inbuf, size_t in_len, char* outbuf, size_t out_sz);

transmit_t
http_server_SWF_transmit(payloads& pl, struct evbuffer *source, conn_t *conn);

recv_t
http_client_SWF_receive (http_steg_t * s, struct evbuffer *dest, char* headers, size_t headers_length, 
			 char* response, size_t response_length);


rcode_t
recover_data(unsigned char* in_swf, size_t in_sz, unsigned char* out_data, size_t out_sz,
	     size_t& rdatalen);

rcode_t
parse_swf(unsigned char* in_swf, size_t in_sz, unsigned char* out_swf, size_t out_sz, 
	  unsigned char* b64_buf, size_t b64_len, size_t& bytes_consumed);



#endif
