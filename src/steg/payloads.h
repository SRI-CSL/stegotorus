/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */


#ifndef _PAYLOADS_H
#define _PAYLOADS_H

#include "headers.h"

/* three files:
   server_data, client data, protocol data
*/

#define CONN_DATA_REQUEST 1  /* payload packet sent by client */
#define CONN_DATA_REPLY 2    /* payload packet sent by server */

#define NO_NEXT_STATE -1

#define MAX_PAYLOADS 10000
#define MAX_RESP_HDR_SIZE 512

// max number of payloads that have enough capacity from which
// we choose the best fit
#define MAX_CANDIDATE_PAYLOADS 10



#define HTML_MIN_AVAIL_SIZE 1026

#define JS_MIN_AVAIL_SIZE 1026
// JS_MIN_AVAIL_SIZE should reflect the min number of data bytes
// a JavaScript may encapsulate

#define PDF_MIN_AVAIL_SIZE 10240
#define PDF_DELIMITER_SIZE 2
#define PDF_MAX_AVAIL_SIZE 100000

/*
 * Per default limit to 1 MiB
 * The largest pentry in our server.out is ~5.5 MiB.
 */
#define HTTP_MSG_BUF_SIZE (1024 * 1024)

/* Maximum we accept for loading */
#define HTTP_MSG_BUF_SIZE_MAX (6 * 1024 * 1024)



// used by the JavaScript steg module to distinguish two cases in which
// JS may appear in the HTTP msg
// 1) CONTENT-TYPE in HTTP header specifies that the HTTP body is a JS
// 2) CONTENT-TYPE corresponds to HTML, and the HTTP body contains JS
//    denoted by script type for JS
#define CONTENT_JAVASCRIPT              1
#define CONTENT_HTML_JAVASCRIPT         2

// payloads for specific content type
//
// MAX_CONTENT_TYPE specifies the maximum number of supported content types
// (e.g. HTTP_CONTENT_JAVASCRIPT is a content type)
//
// initTypePayload[x] specifies whether the arrays typePayloadCount and
// typePayloads for content type x
//
// typePayloadCount[x] specifies the number of available payloads for
// content type x
//
// typePayload[x][] contains references to the corresponding entries in
// payload_hdrs[] and payloads[]
//
// typePayloadCap[x][] specifies the capacity for typePayload[x][]

#include "../pgen.h"
#include "images.h"
#include "protocol.h"
#include "pdfs.h"

struct payloads {
  int init_type_payload[MAX_CONTENT_TYPE];
  int type_payload_count[MAX_CONTENT_TYPE];
  int type_payload[MAX_CONTENT_TYPE][MAX_PAYLOADS];
  int type_payload_cap[MAX_CONTENT_TYPE][MAX_PAYLOADS];

  unsigned int max_JS_capacity;
  unsigned int max_HTML_capacity;
  unsigned int max_PDF_capacity;

  pentry_header payload_hdrs[MAX_PAYLOADS];
  char* payloads[MAX_PAYLOADS];
  unsigned int payload_count;
  image_pool_p pool;
  pdf_pool_p pool_pdf;
};

void zero_payloads(payloads& pl);

int perturb_uri(char* line, size_t len);
bool validate_uri(char* line, size_t len);
void load_payloads(payloads& pl, const char* fname);
void free_payloads(payloads& pl);
int fix_content_len (char* payload, size_t payload_len, char *buf, size_t buf_len);
void init_js_keywords();
rcode_t parse_client_headers(char* inbuf, char* outbuf, int len, size_t& bytes_written);
rcode_t find_client_payload(payloads& pl, char* buf, size_t len, uint16_t type, size_t& bytes_written);

rcode_t init_JS_payload_pool(payloads& pl, uint32_t len, uint16_t type, uint32_t minCapacity);
rcode_t init_SWF_payload_pool(payloads& pl, uint32_t len, uint16_t type, uint32_t minCapacity);
rcode_t init_PDF_payload_pool(payloads& pl, uint32_t len, uint16_t type, uint32_t minCapacity);
rcode_t init_HTML_payload_pool(payloads& pl, uint32_t len, uint16_t type, uint32_t minCapacity);


rcode_t get_next_payload (payloads& pl, uint16_t contentType, char*& buf, size_t& size, size_t& cap);
rcode_t get_payload (payloads& pl, int contentType, int cap, char*& buf, size_t& size);

int has_eligible_HTTP_content (char* buf, size_t len, int type);


void gen_rfc_1123_date(char* buf, size_t buf_size);
void gen_rfc_1123_expiry_date(char* buf, size_t buf_size);

char* str_in_binary (const char *pattern, size_t patternLen, const char *blob, size_t blobLen);
http_content_t find_uri_type(char* buf, size_t buflen);

rcode_t gen_response_header(const char* content_type, const char* cookie, int gzip, size_t length, char* buf,  size_t buflen, size_t& hdrlen);
rcode_t gen_post_header(const char* content_type, const char* cookie, const char* post, const char* host, int gzip, 
			size_t length, char* buf, size_t buflen, size_t& hdrlen);

#endif
