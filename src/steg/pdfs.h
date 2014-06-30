/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */


#ifndef _PDFS_H
#define _PDFS_H

#include <stddef.h>

typedef struct pdf *pdf_p;

typedef struct pdf {
  size_t size;             /* size of the cover pdf      */
  char* path;              /* from whence it came        */
  unsigned char* bytes;    /* the actual pdf             */
  int capacity;            /* amt of data it can carry   */
} pdf_t;


typedef struct pdf_pool *pdf_pool_p;

typedef struct pdf_pool {
  pdf_p   *the_pdfs;                /* an array of pdf_p objects                         */
  int      the_pdfs_length;         /* the capacity (length of) the array                */
  int      the_pdfs_offset;         /* the current empty offset into the array           */
  int      the_pdfs_max_payload;    /* the maximal data capacity of all the pdfs stored  */
} pdf_pool_t;

void free_pdf(pdf_p pp);

pdf_pool_p load_pdfs(const char* path);

int free_pdf_pool(pdf_pool_p pool);

pdf_p get_cover_pdf(pdf_pool_p pool, int size);

#endif
