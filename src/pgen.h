/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef PGEN_H
#define PGEN_H

#define MAX_CONTENT_TYPE 11

#define TYPE_SERVICE_DATA	0x1
#define TYPE_HTTP_REQUEST	0x2
#define TYPE_HTTP_RESPONSE	0x4

#ifdef __GNUC__
#define PACKED __attribute__((packed))
#define ALIGNED __attribute__((aligned))
#define UNUSED __attribute__ ((__unused__))
#else
#define PACKED
#define ALIGNED
#define UNUSED
#endif

/* struct for reading in the payload_gen dump file */
struct pentry_header {
  uint16_t	ptype;
  uint8_t	pad1[2];
  uint32_t	length;
  uint16_t	port;		/* network format */
  uint8_t	pad2[2];
};

#endif
