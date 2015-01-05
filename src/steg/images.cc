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


static const bool images_debug = 0;

static const char* images_log = NULL;

static void
set_jel_log( jel_config *jel );

static bool
configure_from_knobs(jel_knobs_t* knobs, jel_config *jel, bool embedding);

static image_p
load_image(image_pool_p pool, const char* path, char* basename);

static image_p
embed_message_aux(jel_knobs_t* knobs, image_p cover, unsigned char* message, int message_length, unsigned char* destination, int destination_length);

static image_pool_p alloc_image_pool();
static image_pool_p alloc_image_pool(){
  image_pool_p retval =  (image_pool_p)xmalloc(sizeof(image_pool_t));
  /* explicitly zero for emphasis */
  retval->the_images = NULL;
  retval->the_images_length = 0;
  retval->the_images_offset = 0;
  retval->the_images_max_payload = 0;
  retval->the_images_min_payload = -1;
  retval->the_images_source = NULL;
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
    free(pool->the_images_source);
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

image_pool_p load_images(const char* path, int maxcount){
  image_pool_p pool = alloc_image_pool();
  DIR *dirp = NULL;

  if(pool != NULL){
    struct dirent *direntp;

    if((path == NULL) || ((dirp = opendir(path)) == NULL)){
      log_warn("load_images could not open %s", path);
      goto clean_up;
    }

    pool->the_images_source = strdup(path);
    
    while((direntp = readdir(dirp)) != NULL){

      if(pool->the_images_offset > maxcount){  break;  }
      
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

  log_warn("load_images: count now %d", pool->the_images_offset);

  /* need to do something about multiple connections loading multiple images; does this happen with payloads too? */
  if(images_debug){
    log_warn("load_images: min capacity: %d", pool->the_images_min_payload);
    log_warn("load_images: max capacity: %d", pool->the_images_max_payload);
  }
  
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
  set_jel_log(jel);
  int capacity = 0;
  int ret = jel_set_mem_source(jel, image->bytes, image->size);
  if (ret != 0) {
    log_warn("jel: Error - exiting (need a diagnostic!)\n");
  } else {
    capacity = jel_capacity(jel);
  }
  jel_close_log(jel);
  jel_free(jel);
  return capacity;
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

            if(pool->the_images_min_payload < 0){
              pool->the_images_min_payload = image->capacity;
            } else if(image->capacity < pool->the_images_min_payload){
              pool->the_images_min_payload = image->capacity;
            }
            
            if(images_debug){
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

image_p get_image(image_pool_p pool, int size){
  if(pool == NULL){ return NULL; }
  if(size < pool->the_images_max_payload && pool->the_images_offset > 0){
    image_p retval = NULL;
    int index, fails = 0;
    /* try and get a random one first */
    while((retval == NULL) && (fails++ < 10)){
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
  log_warn("get_image failed:  image count = %d; max payload = %d",   pool->the_images_offset, pool->the_images_max_payload);
  return NULL;
}

/* this is a hack; when the dust settles we should do something better */
image_p get_image_by_index(image_pool_p pool, int index){

  if((0 <= index) && (index < pool->the_images_offset)){
    image_p image = NULL;
    /* first try and get it by the name "index".jpg  */
    char file[1024];
    int i;

    snprintf(file, 1024, "%s/%d.jpg", pool->the_images_source, index);

    for(i = 0; i < pool->the_images_offset; i++){
      image_p im = pool->the_images[i];
      if(!strcmp(file, im->path)){
        image = im;
        break;
      } 
    }

    /* else just get the "index"th image in the array */
    if(image == NULL){
      image = pool->the_images[index];
    }
    
    //log_warn("get_image_by_index(%d) yields %s", index, image->path);

    return image;

  }
  return NULL;
}

image_p embed_message(jel_knobs_t* knobs, image_pool_p pool, unsigned char* message, int message_length){
  image_p retval = NULL;
  if(message != NULL){
    image_p cover = get_image(pool, message_length);

    if(cover != NULL){

      retval = embed_message_in_image(knobs, cover, message, message_length);
      
    }
  }
  return retval;
}

image_p embed_message_in_image(jel_knobs_t* knobs, image_p cover, unsigned char* message, int message_length){
  image_p retval = NULL;
  if(images_debug){ log_warn("embed_message_in_image:  %d %s",  message_length, cover->path); }
  int failures = 0, destination_length = cover->size;
  unsigned char* destination = NULL;
  
  do {
    destination_length *= 2;
    free(destination);
    destination = (unsigned char*)xmalloc(destination_length);
    if(destination == NULL){ break; }
    retval = embed_message_aux(knobs, cover, message, message_length, destination, destination_length);
    if(images_debug){ log_warn("embed_message_aux:  %d  %p",  destination_length, retval); }
  } while((failures++ < 10) && (retval == NULL));
  
  if(images_debug && retval != NULL){
    log_warn("embed_message_in_image:  stegged image size = %" PriSize_t,  retval->size);
  }

  if(retval == NULL){
    log_warn("embed_message_in_image:  FAILED culprit = %s", cover->path);
  }
  
  return retval;
}

/* since we have to guess the size of the destination */
static image_p
embed_message_aux(jel_knobs_t* knobs, image_p cover, unsigned char* message, int message_length, unsigned char* destination, int destination_length){
  image_p retval = NULL;
  if(destination != NULL){
    int32_t embed_length = knobs->embed_length;  
    jel_config *jel = jel_init(JEL_NLEVELS);

    set_jel_log(jel);

    if(!configure_from_knobs(knobs, jel, true)){
      log_warn("embed_message_aux: configure_from_knobs failed");
      return 0;
    }
    
    int ret = jel_set_mem_source(jel, cover->bytes, cover->size);
    if (ret != 0) {
      log_warn("embed_message_aux: jel error - setting source memory!");
      return NULL;
    } 

    ret = jel_set_mem_dest(jel, destination, destination_length);
    if (ret != 0) {
      log_warn("embed_message_aux: jel error - setting dest memory!");
      return NULL;
    }

   jel_setprop(jel, JEL_PROP_EMBED_LENGTH, embed_length);

   /* insert the message */
   int bytes_embedded = jel_embed(jel, message, message_length);
   /* figure out the real size of destination */
   if(bytes_embedded >= message_length){ 
     //log_warn("jel: bytes_embedded = %d message_length = %d jel->jpeglen = %d", bytes_embedded, message_length, jel->jpeglen);
     if(jel->jpeglen > 0){
       retval = alloc_image();
       if(cover->path != NULL){
         retval->path = strdup(cover->path);
       }
       retval->bytes = destination;
       retval->size = jel->jpeglen;
     }
   } else {
     int  errcode = jel_error_code(jel);    /* Returns the most recent error code. */
     char *errstr = jel_error_string(jel);  /* Returns the most recent error string. */
     log_warn("jel: bytes_embedded = %d message_length = %d (%d %s) %s", bytes_embedded, message_length, errcode, errstr, cover->path);
   }
   jel_close_log(jel);
   jel_free(jel);
  }  
  return retval;
}

/* if the message_length is not zero, then the message has been embedded without its length, and this is the length to use */
/* if the message_length is zero, then the message has been embedded with its length                                       */
int extract_message(jel_knobs_t* knobs, unsigned char** messagep, int message_length, unsigned char* jpeg_data, unsigned int jpeg_data_length){
  bool embedded_length = (message_length == 0);
  int msglen;
  if((messagep != NULL) && (jpeg_data != NULL)){
    if(images_debug){ log_warn("extract_message:  %u", jpeg_data_length); }
    if(images_debug){ log_warn("jel_knobs:  %s", jel_knobs_info_string(knobs).c_str()); }
    jel_config *jel = jel_init(JEL_NLEVELS);

    set_jel_log(jel);

    if(!configure_from_knobs(knobs, jel, false)){
      log_warn("extract_message: configure_from_knobs failed");
      return 0;
    }

    int ret = jel_set_mem_source(jel, jpeg_data, jpeg_data_length);
    
    if(ret != 0){
      log_warn("extract_message: jel_set_mem_source failed: %d", ret);
      return 0;
    }

    if(embedded_length){
      msglen = jel_capacity(jel);
    } else {
      msglen = message_length;
    }


    if(images_debug){ log_warn("extract_message: capacity = %d", msglen); }
    unsigned char* message = (unsigned char*) jel_alloc_buffer( jel );
    //unsigned char* message = (unsigned char*)xzalloc(msglen+1);
    jel_setprop(jel, JEL_PROP_EMBED_LENGTH, embedded_length);
    msglen = jel_extract(jel, message, msglen);
    if(images_debug){ log_warn("extract_message: %d bytes extracted", msglen); }
    jel_close_log(jel);
   jel_free(jel);
    *messagep = message;
    return msglen;
  }
  return 0;
}



static void set_jel_log( jel_config *jel ){
  int ret;
  if(images_log == NULL){
    images_log = get_log_path();
  }
  if(images_log != NULL){
    ret = jel_open_log(jel, (char *)images_log);
    if (ret == JEL_ERR_CANTOPENLOG) {
      log_warn("set_jel_log: can't open %s!", images_log);
      jel->logger = stderr;
    }
  }
}

static bool configure_from_knobs(jel_knobs_t* knobs, jel_config *jel, bool embedding){
  
  if(images_debug){
    log_warn("jel_knobs(%p, %p, %d):  %s", knobs, jel, embedding, jel_knobs_info_string(knobs).c_str());
  }


  /*

  int32_t seed = knobs->random_seed;   

  if(seed > 0){
    if(images_debug){ log_warn("Setting frequency generation seed to %d\n", seed); }
    if ( jel_setprop( jel, JEL_PROP_FREQ_SEED, seed ) != seed ){
      log_warn("Failed to set frequency generation seed.\n");
      return false;
    }
  }

  */


  if(embedding){
    int32_t quality = knobs->quality_out;
    if(images_debug){ log_warn("Setting output quality to %d\n", quality); }
    if ( jel_setprop( jel, JEL_PROP_QUALITY, quality ) != quality ){
      log_warn("Failed to set output quality.\n");
      return false;
    }
  }
  
  int32_t freq_pool = knobs->freq_pool;  
  if(images_debug){ log_warn("Setting nfreqs to %d\n", freq_pool); }
  if ( jel_setprop( jel, JEL_PROP_NFREQS, freq_pool ) != freq_pool ){
    log_warn("Failed to set frequency pool\n");
    return false;
  }

  bool    use_ecc = knobs->use_ecc;          
  int32_t ecc_blocklen = knobs->ecc_blocklen;     
  if(images_debug){ log_warn("Setting ecc preferences\n"); }
  if (!use_ecc) {
    jel_setprop(jel, JEL_PROP_ECC_METHOD, JEL_ECC_NONE);
    if(images_debug){ log_warn("Disabling ECC.  getprop=%d\n", jel_getprop(jel, JEL_PROP_ECC_METHOD)); }
  } else if (ecc_blocklen > 0) {
    jel_setprop(jel, JEL_PROP_ECC_BLOCKLEN, ecc_blocklen);
    if(images_debug){ log_warn("ECC block length set to %d.  getprop=%d\n", ecc_blocklen, jel_getprop(jel, JEL_PROP_ECC_BLOCKLEN)); }
  }
  
  return true;
}

