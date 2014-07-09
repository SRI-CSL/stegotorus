/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "images.h"
#include "oshacks.h"

#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>

#include <jel/jel.h>

#define EMBED_LENGTH 1
#define IMAGES_LOG   "/tmp/stegojello.log"

#define IMAGES_DEBUG 0

static image_p load_image(image_pool_p pool, const char* path, char* basename);
static image_p embed_message_aux(image_p cover, unsigned char* message, int message_length, unsigned char* destination, int destination_length);

static image_pool_p alloc_image_pool();
static image_pool_p alloc_image_pool(){
  image_pool_p retval =  (image_pool_p)xmalloc(sizeof(image_pool_t));
  /* explicitly zero for emphasis */
  retval->the_images = NULL;
  retval->the_images_length = 0;
  retval->the_images_offset = 0;
  retval->the_images_max_payload = 0;
  return retval;
}


int free_image_pool(image_pool_p pool){
  int retval = 0;
  if(pool != NULL){
    for(int index = 0; index < pool->the_images_offset; index++){
      free_image(pool->the_images[index]);
      retval++;
    }
    
    free(pool->the_images);
    pool->the_images = NULL;
    pool->the_images_length = 0;
    pool->the_images_offset = 0;
    free(pool);
  }
  return retval;
}

static bool grow_the_images(image_pool_p pool);
static bool grow_the_images(image_pool_p pool){
  if(pool != NULL){
    int temp_length = 2 * (pool->the_images_length == 0 ? 1 : pool->the_images_length);
    image_p *temp_images = (image_p *)xzalloc(sizeof(image_p) * temp_length);
    if(temp_images != NULL){
      int index;
      for(index = 0; index < pool->the_images_offset; index++){
        temp_images[index] = pool->the_images[index];
      }
      free(pool->the_images);
      pool->the_images = temp_images;
      pool->the_images_length = temp_length;
      return true;
    } 
  }
  return false;
}

image_pool_p load_images(const char* path){
  image_pool_p pool = alloc_image_pool();
  DIR *dirp = NULL;

  if(pool != NULL){
    struct dirent *direntp;

    if((path == NULL) || ((dirp = opendir(path)) == NULL)){
      log_warn("load_images could not open %s", path);
      goto clean_up;
    }

    while((direntp = readdir(dirp)) != NULL){

      //only load the first 20
      if(pool->the_images_offset > 20){  break;  }
      
      /* might also want to filter on the extension */
      if((strcmp(direntp->d_name, ".") == 0) || (strcmp(direntp->d_name, "..") == 0)){
        continue;
      }

      image_p image = load_image(pool, path, direntp->d_name);
      
      if(image != NULL){
        if(((pool->the_images_length == 0) || (pool->the_images_offset + 1 == pool->the_images_length)) && !grow_the_images(pool)){
          log_warn("load_images could not grow storage");
          free(image);
          goto clean_up;
        }
        
        pool->the_images[pool->the_images_offset++] = image;
      }
    }

  }
  
 clean_up:

  if(dirp != NULL){
    while((closedir(dirp) == -1) && (errno  == EINTR)){ };
  }

  /* need to do something about multiple connections loading multiple images; does this happen with payloads too? */
  log_warn("load_images: count now %d", pool->the_images_offset);
  
  if(pool->the_images_offset == 0){
    free_image_pool(pool);
    pool = NULL;
  }
  
  return pool;
}

static image_p alloc_image();
static image_p alloc_image(){
  return (image_p)xzalloc(sizeof(image_t));
}

void free_image(image_p im){
  if(im != NULL){
    free(im->bytes);
    free(im->path);
    free(im);
  }
}

static bool file2bytes(const char* path, unsigned char* bytes, size_t bytes_wanted);
static bool file2bytes(const char* path, unsigned char* bytes, size_t bytes_wanted){
  FILE *f;
  size_t bytes_read;
  f = fopen(path, "rb");
  if (f == NULL) { 
    log_warn("load_image fopen(%s) failed; %s", path, strerror(errno));
    return false;
  }
  /* not very signal proof */
  bytes_read = fread(bytes, sizeof(unsigned char), bytes_wanted, f);
  if(bytes_read < bytes_wanted){
    log_warn("load_image fread(%s) only read %" PriSize_t " of %" PriSize_t " bytes", path, bytes_read, bytes_wanted);
    return false;
  } else {
    return true;
  }
}

/* a playground at present */
static int capacity(image_p image){
  jel_config *jel = jel_init(JEL_NLEVELS);
  int ret = jel_open_log(jel, (char *)IMAGES_LOG);
  if (ret == JEL_ERR_CANTOPENLOG) {
    log_warn("Can't open %s!", IMAGES_LOG);
    jel->logger = stderr;
  }
  ret = jel_set_mem_source(jel, image->bytes, image->size);
  if (ret != 0) {
    log_warn("jel: Error - exiting (need a diagnostic!)\n");
  } else {
    ret = jel_capacity(jel);
  }
  jel_close_log(jel);
  jel_free(jel);
  return ret;
}

static image_p load_image(image_pool_p pool, const char* path, char* basename){
  char name[2048];
  /* none of this is very platform independant; sorry */
  if(snprintf(name, 2048, "%s/%s", path, basename) >= 2048){
    log_warn("load_image path too long: %s/%s", path, basename);
    return NULL;
  } else {
    struct stat statbuff;
    if(stat(name, &statbuff) == -1){
      log_warn("load_image could not stat %s", name);
      return NULL;
    }
    if(S_ISREG(statbuff.st_mode)){
      image_p image = alloc_image();
      if(image != NULL){
        image->path = strdup(name);
        image->size = statbuff.st_size;
        image->bytes = (unsigned char *)xmalloc(image->size);
        if(image->bytes != NULL){
          int success = file2bytes(image->path, image->bytes, image->size);
          if(success){
            /* do the jel analysis here */
            image->capacity = capacity(image);
            if(image->capacity >=  pool->the_images_max_payload){
              pool->the_images_max_payload = image->capacity;
            }
            if(IMAGES_DEBUG){
              log_warn("load_image loaded %s of size %" PriSize_t " with capacity %d", image->path, image->size, image->capacity);
            }
            return image;
          } else {
            free_image(image);
          }
        }
      }
    }
    return NULL;
  }
}

static image_p get_cover_image(image_pool_p pool, int size);
static image_p get_cover_image(image_pool_p pool, int size){
  if(pool == NULL){ return NULL; }
  if(size < pool->the_images_max_payload && pool->the_images_offset > 0){
    image_p retval = NULL;
    int index, fails = 0;
    /* try and get a random one first */
    while((retval != NULL) && (fails++ < 10)){
      index = rand() % pool->the_images_offset;
      retval = pool->the_images[index];
      if(retval->capacity > size){
        return retval;
      } else {
        retval = NULL;
      }
    }
    /* haven't got one yet; after 10 tries! better just return the first that works */
    for(index = 0; index < pool->the_images_offset; index++){
      retval = pool->the_images[index];
      if(retval->capacity > size){
        return retval;
      }
    }
  }  
  log_warn("get_cover_image failed:  image count = %d; max payload = %d",   pool->the_images_offset, pool->the_images_max_payload);
  return NULL;
}

image_p embed_message(image_pool_p pool, unsigned char* message, int message_length);
image_p embed_message(image_pool_p pool, unsigned char* message, int message_length){
  image_p retval = NULL;
  if(message != NULL){
    image_p cover = get_cover_image(pool, message_length);
    if(cover != NULL){
      if(IMAGES_DEBUG){ log_warn("embed_message:  %d %s",  message_length, cover->path); }
      int failures = 0, destination_length = cover->size;
      unsigned char* destination = NULL;
      
      do {
        destination_length *= 2;
        free(destination);
        destination = (unsigned char*)xmalloc(destination_length);
        if(destination == NULL){ break; }
        retval = embed_message_aux(cover, message, message_length, destination, destination_length);
        if(IMAGES_DEBUG){ log_warn("embed_message_aux:  %d  %p",  destination_length, retval); }
      } while((failures++ < 10) && (retval == NULL));

      if(IMAGES_DEBUG && retval != NULL){
        log_warn("embed_message:  stegged image size = %" PriSize_t,  retval->size);
      }
    }
  }
  return retval;
}

/* since we have to guess the size of the destination */
static image_p embed_message_aux(image_p cover, unsigned char* message, int message_length, unsigned char* destination, int destination_length){
  image_p retval = NULL;
  if(destination != NULL){
    jel_config *jel = jel_init(JEL_NLEVELS);
    int ret = jel_open_log(jel, (char *)IMAGES_LOG);
    int bytes_embedded = 0;
    if (ret == JEL_ERR_CANTOPENLOG) {
      log_warn("extract_message: can't open %s!", IMAGES_LOG);
      jel->logger = stderr;
    }
    ret = jel_set_mem_source(jel, cover->bytes, cover->size);
    if (ret != 0) {
      log_warn("jel: error - setting source memory!");
      return NULL;
    } 
    ret = jel_set_mem_dest(jel, destination, destination_length);
    if (ret != 0) {
      log_warn("jel: error - setting dest memory!");
      return NULL;
    } 
   jel_setprop(jel, JEL_PROP_EMBED_LENGTH, EMBED_LENGTH);

   /* insert the message */
   bytes_embedded = jel_embed(jel, message, message_length);
   /* figure out the real size of destination */
   if(bytes_embedded >= message_length){ 
     //log_warn("jel: bytes_embedded = %d message_length = %d jel->jpeglen = %d", bytes_embedded, message_length, jel->jpeglen);
     if(jel->jpeglen > 0){
       retval = alloc_image();
       retval->bytes = destination;
       retval->size = jel->jpeglen;
     }
   } else {
     int  errcode = jel_error_code(jel);    /* Returns the most recent error code. */
     char *errstr = jel_error_string(jel);  /* Returns the most recent error string. */
     log_warn("jel: bytes_embedded = %d message_length = %d (%d %s)", bytes_embedded, message_length, errcode, errstr);
   }
   jel_close_log(jel);
   jel_free(jel);
  }  
  return retval;
}


int extract_message(unsigned char** messagep, unsigned char* jpeg_data, unsigned int jpeg_data_length){
  if((messagep != NULL) && (jpeg_data != NULL)){
    if(IMAGES_DEBUG){ log_warn("extract_message:  %u", jpeg_data_length); }
    jel_config *jel = jel_init(JEL_NLEVELS);
    int ret = jel_open_log(jel, (char *)IMAGES_LOG);
    if (ret == JEL_ERR_CANTOPENLOG) {
      log_warn("extract_message: can't open %s!", IMAGES_LOG);
      jel->logger = stderr;
    }
    ret = jel_set_mem_source(jel, jpeg_data, jpeg_data_length);
    if(ret != 0){
      log_warn("extract_message: jel_set_mem_source failed: %d", ret);
      return 0;
    }
    int msglen = jel_capacity(jel);
    if(IMAGES_DEBUG){ log_warn("extract_message: capacity = %d", msglen); }
    unsigned char* message = (unsigned char*)xzalloc(msglen+1);
    jel_setprop(jel, JEL_PROP_EMBED_LENGTH, EMBED_LENGTH);
    msglen = jel_extract(jel, message, msglen);
    if(IMAGES_DEBUG){ log_warn("extract_message: %d bytes extracted", msglen); }
    jel_close_log(jel);
   jel_free(jel);
    *messagep = message;
    return msglen;
  }
  return 0;
}
