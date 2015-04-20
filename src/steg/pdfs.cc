/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "pdfs.h"
#include "pdfSteg.h"
#include "payloads.h"
#include "oshacks.h"

#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>

#define PDFS_DEBUG 0
#define MAX_PDF_POOL_SIZE 20

static pdf_p load_pdf(pdf_pool_p pool, const char* path, char* basename);



static pdf_pool_p alloc_pdf_pool();
static pdf_pool_p 
alloc_pdf_pool()
{
  pdf_pool_p retval =  (pdf_pool_p)xmalloc(sizeof(pdf_pool_t));
  /* explicitly zero for emphasis */
  retval->the_pdfs = NULL;
  retval->the_pdfs_length = 0;
  retval->the_pdfs_offset = 0;
  retval->the_pdfs_max_payload = 0;
  return retval;
}


int 
free_pdf_pool(pdf_pool_p pool)
{
  int retval = 0;

  if(pool != NULL) {
    for(int index = 0; index < pool->the_pdfs_offset; index++){
      free_pdf(pool->the_pdfs[index]);
      retval++;
    }
    
    free(pool->the_pdfs);
    pool->the_pdfs = NULL;
    pool->the_pdfs_length = 0;
    pool->the_pdfs_offset = 0;
    free(pool);
  }
  return retval;
}



static bool grow_the_pdf_pool(pdf_pool_p pool);
static bool 
grow_the_pdf_pool(pdf_pool_p pool)
{
  if(pool != NULL){
    int temp_length = 2 * (pool->the_pdfs_length == 0 ? 1 : pool->the_pdfs_length);
    pdf_p *temp_pdfs = (pdf_p *)xzalloc(sizeof(pdf_p) * temp_length);

    if(temp_pdfs != NULL){
      int index;

      for(index = 0; index < pool->the_pdfs_offset; index++){
        temp_pdfs[index] = pool->the_pdfs[index];
      }
      free(pool->the_pdfs);
      pool->the_pdfs = temp_pdfs;
      pool->the_pdfs_length = temp_length;
      return true;
    } 
  }
  return false;
}



int usable_pdf(const char* pdf_start, size_t pdf_size);
int
usable_pdf(const char* pdf_start, size_t pdf_size)
{
  const char *pdf_end = pdf_start + pdf_size;
  char *endp, *xrefp, *xrefp2, *startxrefp, *startxrefp2;

  endp = str_in_binary(STREAM_END, STREAM_END_SIZE, pdf_start, pdf_size);

  if (endp == NULL) {
    goto err;
  }

  // check if one can find exactly one xref table after endstream
  xrefp = str_in_binary("\nxref", 5, pdf_start, pdf_size);

  if (xrefp == NULL || xrefp < endp) {
    goto err;
  }

  startxrefp = str_in_binary("startxref", 9, pdf_start, pdf_size);

  if (startxrefp == NULL || startxrefp < endp || startxrefp < xrefp) {
    goto err;
  }

  // and no more xref table after that
  xrefp2 = str_in_binary("\nxref", 5, xrefp+5, pdf_end-(xrefp+5));
  startxrefp2 = str_in_binary("startxref", 9, startxrefp+9, pdf_end-(startxrefp+9));

  if (xrefp2 != NULL || startxrefp2 != NULL) {
    goto err;
  }

  log_debug("usable_pdf: pdf passed the usability check");
  return 1;

 err:
  log_debug("usable_pdf: pdf not usable");
  return 0;
}



pdf_pool_p 
load_pdfs(const char* path)
{
  pdf_pool_p pool = alloc_pdf_pool();
  DIR *dirp = NULL;
    
  if(pool != NULL){
    struct dirent *direntp;

    if((path == NULL) || ((dirp = opendir(path)) == NULL)){
      log_warn("load_pdfs could not open %s", path);
      goto clean_up;
    }

    while((direntp = readdir(dirp)) != NULL){

      //only load the first MAX_PDF_POOL_SIZE
      if(pool->the_pdfs_offset > MAX_PDF_POOL_SIZE){  break; }
      
      /* might also want to filter on the extension */
      if((strcmp(direntp->d_name, ".") == 0) || (strcmp(direntp->d_name, "..") == 0)){
        continue;
      }

      pdf_p pdfp = load_pdf(pool, path, direntp->d_name);

      if(pdfp != NULL){
        if(((pool->the_pdfs_length == 0) || (pool->the_pdfs_offset + 1 == pool->the_pdfs_length)) && !grow_the_pdf_pool(pool)){
          log_warn("load_pdfs could not grow storage");
          free_pdf(pdfp);
          goto clean_up;
        }
        pool->the_pdfs[pool->the_pdfs_offset++] = pdfp;
      }
    }

  }
  
 clean_up:

  if(dirp != NULL){
    while((closedir(dirp) == -1) && (errno  == EINTR)){ };
  }

  /* need to do something about multiple connections loading multiple pdfs; does this happen with payloads too? */
  log_warn("load_pdfs: count now %d", pool->the_pdfs_offset);
  
  if(pool->the_pdfs_offset == 0){
    log_warn("load_pdfs: No usable pdf files found in %s; need a pdf file that contains a stream object and has exactly one xref table at the end", path);
    free_pdf_pool(pool);
    pool = NULL;
  }
  
  return pool;
}


static pdf_p alloc_pdf();
static pdf_p 
alloc_pdf()
{
  return (pdf_p)xzalloc(sizeof(pdf_t));
}


void 
free_pdf(pdf_p pdfp)
{
  if(pdfp != NULL){
    free(pdfp->bytes);
    free(pdfp->path);
    free(pdfp);
  }
}


static bool file2bytes(const char* path, unsigned char* bytes, size_t bytes_wanted);
static bool 
file2bytes(const char* path, unsigned char* bytes, size_t bytes_wanted)
{
  FILE *f;
  size_t bytes_read;
  f = fopen(path, "rb");

  if (f == NULL) { 
    log_warn("file2bytes: fopen(%s) failed; %s", path, strerror(errno));
    return false;
  }
  /* not very signal proof */
  bytes_read = fread(bytes, sizeof(unsigned char), bytes_wanted, f);

  fclose(f);
  
  if(bytes_read < bytes_wanted){
    log_warn("file2bytes: fread(%s) only read %" PriSize_t " of %" PriSize_t " bytes", path, bytes_read, bytes_wanted);
    return false;
  } else {
    return true;
  }
}


/* capacity returns a fixed val */
static int 
capacity(pdf_p /* pdf */)
{
  return PDF_SIZE_CEILING;
}


static pdf_p 
load_pdf(pdf_pool_p pool, const char* path, char* basename)
{
  char name[2048];
  /* none of this is very platform independant; sorry */

  if(snprintf(name, 2048, "%s/%s", path, basename) >= 2048){
    log_warn("load_pdf path too long: %s/%s", path, basename);
    return NULL;
  } else {
    struct stat statbuff;

    if(stat(name, &statbuff) == -1){
      log_warn("load_pdf could not stat %s", name);
      return NULL;
    }

    if(S_ISREG(statbuff.st_mode)){
      pdf_p pdfp = alloc_pdf();

      if(pdfp != NULL){
        pdfp->path = strdup(name);
        pdfp->size = statbuff.st_size;
        pdfp->bytes = (unsigned char *)xmalloc(pdfp->size);

        if(pdfp->bytes != NULL){
          int success = file2bytes(pdfp->path, pdfp->bytes, pdfp->size);

          if(success){
            success = usable_pdf((const char*)(pdfp->bytes), pdfp->size);
          }

          if(success){
            pdfp->capacity = capacity(pdfp);

            if(pdfp->capacity >=  pool->the_pdfs_max_payload){
              pool->the_pdfs_max_payload = pdfp->capacity;
            }

            if(PDFS_DEBUG){
              log_warn("load_pdf loaded %s of size %" PriSize_t " with capacity %d", pdfp->path, pdfp->size, pdfp->capacity);
            }
            return pdfp;
          } else {
            free_pdf(pdfp);
          }
        }
      }
    }
    return NULL;
  }
}


pdf_p get_cover_pdf(pdf_pool_p pool, int size);
pdf_p 
get_cover_pdf(pdf_pool_p pool, int size)
{
  if(pool == NULL){ return NULL; }

  if(size <= pool->the_pdfs_max_payload && pool->the_pdfs_offset > 0){
    pdf_p retval = NULL;
    int index, fails = 0;

    log_debug("BEFORE WHILE: get_cover_pdf size %d", size);

    /* try and get a random one first */
    while((retval == NULL) && (fails++ < 10)){
      index = randomg() % pool->the_pdfs_offset;

      log_debug("INDEX: get_cover_pdf got random index %d", index);

      retval = pool->the_pdfs[index];
      log_debug("PRE: get_cover_pdf randomly picked index %d with capacity %d; needed %d", index, retval->capacity, size);

      if(retval->capacity >= size){
        log_debug("OK: get_cover_pdf randomly picked index %d with capacity %d", index, retval->capacity);
        return retval;
      } else {
        log_debug("FAILED: get_cover_pdf randomly picked index %d with capacity %d but needed %d", index, retval->capacity, size);
        retval = NULL;
      }
    }

    /* haven't got one yet; after 10 tries! better just return the first that works */
    for(index = 0; index < pool->the_pdfs_offset; index++){
      retval = pool->the_pdfs[index];
      if(retval->capacity >= size){
        log_debug("FALLBACK: get_cover_pdf used index %d with capacity %d", index, retval->capacity);
        return retval;
      }
    }
  }
  log_warn("get_cover_pdf failed:  offset = %d; max payload = %d; req size = %d",   pool->the_pdfs_offset, pool->the_pdfs_max_payload, size);
  return NULL;
}



