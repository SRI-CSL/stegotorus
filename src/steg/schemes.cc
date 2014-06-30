#include "schemes.h"

#include "headers.h"
#include "util.h"
#include "jsonSteg.h"
#include "jpegSteg.h"
#include "pdfSteg.h"
#include "rawSteg.h"
#include "jsutil.h"
#include "strncasestr.h"
#include "oshacks.h"



/*
 *  Cookie transmit uses payloads for URI (thus best to turn off if testing just one scheme)
 *
 *  Posts can all be off.
 *
 *  Need at least one GET
 *
 *  There are no "raw" payloads so cookie transmit and raw should not be on at the same time.
 *
 * 
 */
static bool enabled_schemes[STEG_TRANSPORT_SCHEMES_MAX] = {
  1   /* COOKIE_TRANSMIT */,
  1   /* URI_TRANSMIT    */,
  1   /* JSON_POST       */,
  0   /* PDF_POST        */,
  1   /* JPEG_POST       */,
  0   /* RAW_POST        */,
  1   /* SWF_GET         */,
  1   /* PDF_GET         */,
  1   /* JS_GET          */,
  1   /* HTML_GET        */,
  1   /* JSON_GET        */,       
  1   /* JPEG_GET        */,       
  0   /* RAW_GET         */,       
};


int
schemes_init ()
{
  /*
    this logic could change; so beware but currently if json is all you got upstream,
    then json is all you got downstream too.
   */
  if( !enabled_schemes[COOKIE_TRANSMIT] && !enabled_schemes[URI_TRANSMIT] ){
    log_debug("cookie and uri transmit; both off cascading off switch");
    enabled_schemes[SWF_GET]  = 0;
    enabled_schemes[PDF_GET]  = 0;
    enabled_schemes[JS_GET]   = 0;
    enabled_schemes[HTML_GET] = 0;
    enabled_schemes[JSON_GET] = 0;
    enabled_schemes[JPEG_GET] = 0;
    enabled_schemes[RAW_GET]  = 0;
  }

  return 0;
}

bool schemes_set_scheme(int scheme, int value){

  assert( 0 <= scheme  && scheme < STEG_TRANSPORT_SCHEMES_MAX);

  if( (0 == value) || (1 == value) ){
    enabled_schemes[scheme] = value;
    return true;
  } else {
    return false;
  }

}





int
schemes_get_transmit_scheme (size_t size)
{
  int retval = -1, coin_toss = rand() % 4;
  
  if(enabled_schemes[URI_TRANSMIT] && size < 300){
    retval = URI_TRANSMIT;
  } else if(enabled_schemes[COOKIE_TRANSMIT] && size < 700){
    retval = COOKIE_TRANSMIT;
  } else if(enabled_schemes[JSON_POST] &&  (coin_toss == 0) && (size <= JSON_SIZE_CEILING)){
    retval = JSON_POST;
  } else if(enabled_schemes[JPEG_POST] && (coin_toss == 1) && (size <= JPEG_SIZE_CEILING)){
    retval = JPEG_POST;
  } else if(enabled_schemes[RAW_POST] && (coin_toss == 2) && (size <= RAW_SIZE_CEILING)){
    retval = RAW_POST;
  } else if(enabled_schemes[PDF_POST] && (coin_toss == 3) && (size <= PDF_SIZE_CEILING)){
    retval = PDF_POST;
  } else {
    if(enabled_schemes[COOKIE_TRANSMIT] && (size <=  (MAX_COOKIE_SIZE*3)/4)){
      retval = COOKIE_TRANSMIT;
    } else {
      /* need to use one; presumably because we said we could to transmit_room */
      if((enabled_schemes[JSON_POST]) && (size <= JSON_SIZE_CEILING)){
        retval = JSON_POST;
      } else if((enabled_schemes[JPEG_POST]) && (size <= JPEG_SIZE_CEILING)){
        retval = JPEG_POST;
      } else if((enabled_schemes[RAW_POST]) && (size <= RAW_SIZE_CEILING)){
        retval = RAW_POST;
      } else if((enabled_schemes[PDF_POST]) && (size <= PDF_SIZE_CEILING)){
        retval = PDF_POST;
      } else {
        log_warn("schemes_get_transmit_scheme(%d) = %d; no ENABLED candidate", (int)size, retval);
      }
    }
  }
  /* log_warn("schemes_get_transmit_scheme(%d) = %d", (int)size, retval); */
  return retval;
}


const char *schemes_to_string(int scheme){
  switch(scheme){
  case COOKIE_TRANSMIT: return "COOKIE_TRANSMIT";
  case URI_TRANSMIT:    return "URI_TRANSMIT";
  case JSON_POST:       return "JSON_POST";
  case PDF_POST:        return "PDF_POST";
  case JPEG_POST:       return "JPEG_POST";
  case RAW_POST:        return "RAW_POST";
  case SWF_GET:         return "SWF_GET";
  case PDF_GET:         return "PDF_GET";
  case JS_GET:          return "JS_GET";
  case HTML_GET:        return "HTML_GET";
  case JSON_GET:        return "JSON_GET";
  case JPEG_GET:        return "JPEG_GET";
  case RAW_GET:         return "RAW_GET";
  default:              return "BAD_SCHEME";
  }
}


int schemes_string_to_scheme(const char* scheme_name){

  assert(scheme_name != NULL);

  if(!STRNCMPCONST(scheme_name, "cookie-transmit")){
    return COOKIE_TRANSMIT;
  }
  else if(!STRNCMPCONST(scheme_name, "uri-transmit")){
    return URI_TRANSMIT;
  }
  else if(!STRNCMPCONST(scheme_name, "json-post")){
    return JSON_POST;
  }
  else if(!STRNCMPCONST(scheme_name, "pdf-post")){
    return PDF_POST;
  }
  else if(!STRNCMPCONST(scheme_name, "jpeg-post")){
    return JPEG_POST;
  }
  else if(!STRNCMPCONST(scheme_name, "raw-post")){
    return RAW_POST;
  }
  else if(!STRNCMPCONST(scheme_name, "swf-get")){
    return SWF_GET;
  }
  else if(!STRNCMPCONST(scheme_name, "pdf-get")){
    return PDF_GET;
  }
  else if(!STRNCMPCONST(scheme_name, "js-get")){
    return JS_GET;
  }
  else if(!STRNCMPCONST(scheme_name, "html-get")){
    return HTML_GET;
  }
  else if(!STRNCMPCONST(scheme_name, "json-get")){
    return JSON_GET;
  }
  else if(!STRNCMPCONST(scheme_name, "jpeg-get")){
    return JPEG_GET;
  }
  else if(!STRNCMPCONST(scheme_name, "raw-get")){
    return RAW_GET;
  }
    return -1;
}

/*
  this is used in cookie transmit (i.e. http_client_cookie_transmit) to filter the payloads.
  if lots of things are turned off we may need a fall back scheme.
*/
bool schemes_is_enabled(int content_type){
  switch(content_type){
  case HTTP_CONTENT_NONE:          return false;
  case HTTP_CONTENT_JAVASCRIPT:    return enabled_schemes[JS_GET];
  case HTTP_CONTENT_PDF:           return enabled_schemes[PDF_GET];
  case HTTP_CONTENT_SWF:           return enabled_schemes[SWF_GET];
  case HTTP_CONTENT_ENCRYPTEDZIP:  return false;
  case HTTP_CONTENT_HTML:          return enabled_schemes[HTML_GET];
  case HTTP_CONTENT_JSON:          return enabled_schemes[JSON_GET];
  case HTTP_CONTENT_JPEG:          return enabled_schemes[JPEG_GET];
  case HTTP_CONTENT_RAW:           return enabled_schemes[RAW_GET];
  default:  return false;
  }
}


static int successful_receptions[HTTP_CONTENT_TYPES_MAX] = {};

static int corrupted_receptions[HTTP_CONTENT_TYPES_MAX] = {};

static void
receptions_reset (int content_type)
{
  //periodically reset
  if (rand() % 40 == 0) {
    successful_receptions[content_type] = 0;
    corrupted_receptions[content_type] = 0;
  }
}


bool
schemes_is_usable (int content_type)
{
  /*
   * Make sure we do not go out of bounds
   * though we can't check how long the counts are...
   */
  if ( content_type >= HTTP_CONTENT_TYPES_MAX) {
    log_warn("invalid payload content_type\n");
    return false;
  }
  // we haven't tried using this payload content_type enough times yet...
  if ( successful_receptions[content_type] + corrupted_receptions[content_type]  < 6 ){
    return true;
  }
  // seems like this payload content_type gets corrupted more often than not...
  if ( successful_receptions[content_type] == 0 || ((corrupted_receptions[content_type]  / successful_receptions[content_type]) > 2)){
    return false;
  }
  return true;
}

void
schemes_success (int content_type)
{
  if ( content_type >= HTTP_CONTENT_TYPES_MAX ) {  return;  }
  successful_receptions[content_type]++;
  log_debug("In successful reception %d %d", content_type, successful_receptions[content_type]);
  receptions_reset(content_type);
}

void
schemes_failure (int content_type)
{
  if ( content_type >= HTTP_CONTENT_TYPES_MAX ) {  return;  }
  corrupted_receptions[content_type]++;
  log_warn("\n\n In corrupted reception %d %d\n\n", content_type, corrupted_receptions[content_type]);
  receptions_reset(content_type);
}

int
schemes_clientside_transmit_room (payloads& /* payloads */, size_t /* pref */, size_t& lo, size_t& hi)
{
  bool set = false;
  if(enabled_schemes[COOKIE_TRANSMIT]){
    /* MIN_COOKIE_SIZE and MAX_COOKIE_SIZE are *after* base64'ing */
    if (lo < (MIN_COOKIE_SIZE*3)/4)
      lo = (MIN_COOKIE_SIZE*3)/4;
  
    if (hi > (MAX_COOKIE_SIZE*3)/4)
      hi = (MAX_COOKIE_SIZE*3)/4;
    set = true;
  }
  
  if(enabled_schemes[JSON_POST] ){
    hi = JSON_SIZE_CEILING;
    set = true;
  }
  
  if(enabled_schemes[JPEG_POST] ){
    hi = JPEG_SIZE_CEILING;
    set = true;
  }

  if(enabled_schemes[PDF_POST] ){
    hi = PDF_SIZE_CEILING;
    set = true;
  }

  if(enabled_schemes[RAW_POST] ){
    hi = RAW_SIZE_CEILING;
    set = true;
  }
  
  if(!set){
    hi = 1024;
    log_warn("schemes_clientside_transmit_room NO CANDIDATES lo=%" PriSize_t " hi=%" PriSize_t, lo, hi);
  }
  
  //log_warn("schemes_clientside_transmit_room lo=%lu hi=%lu", lo, hi);
  return 0;
}

int
schemes_serverside_transmit_room (payloads&  payloads, int content_type, size_t /* pref */, size_t& lo, size_t& hi)
{
  switch (content_type) {
  case HTTP_CONTENT_SWF:
    if (hi >= 256)
      hi = 256;
    break;
    
  case HTTP_CONTENT_JAVASCRIPT:
    if (hi >= payloads.max_JS_capacity)
      hi = payloads.max_JS_capacity;
    break;
    
  case HTTP_CONTENT_HTML:
    if (hi >= payloads.max_HTML_capacity)
      hi = payloads.max_HTML_capacity;
    break;
    
  case HTTP_CONTENT_PDF:
    if (hi >= PDF_MIN_AVAIL_SIZE)
      hi = PDF_MIN_AVAIL_SIZE;
    break;

  case HTTP_CONTENT_JSON:
    hi = JSON_SIZE_CEILING;
    break;

  case HTTP_CONTENT_JPEG:
    hi = JPEG_SIZE_CEILING;
    break;

  case HTTP_CONTENT_RAW:
    hi = RAW_SIZE_CEILING;
    break;

  default:
    log_warn("schemes_serverside_transmit_room: unknown content_type %d lo=%" PriSize_t " hi=%" PriSize_t, content_type, lo, hi);
    hi = 512;
  }
  
  return 0;
}


void
schemes_clientside_init (payloads& payloads, const char* imagedir, const char* pdfdir)
{
  if(enabled_schemes[JS_GET]){ init_js_keywords(); }
    
  if(enabled_schemes[PDF_POST]){
    init_PDF_payload_pool(payloads, HTTP_MSG_BUF_SIZE, TYPE_HTTP_RESPONSE, PDF_MIN_AVAIL_SIZE);
  }

  if(enabled_schemes[JPEG_POST]){
    payloads.pool = load_images(imagedir);
  }

  if(enabled_schemes[PDF_POST]){
    payloads.pool_pdf = load_pdfs(pdfdir);
  }

}

void
schemes_serverside_init (payloads& payloads, const char* imagedir, const char* pdfdir)
{
  if(enabled_schemes[JS_GET]){
    init_js_keywords();
    init_JS_payload_pool(payloads, HTTP_MSG_BUF_SIZE, TYPE_HTTP_RESPONSE, JS_MIN_AVAIL_SIZE);
  }
  if(enabled_schemes[HTML_GET]){
    init_HTML_payload_pool(payloads, HTTP_MSG_BUF_SIZE, TYPE_HTTP_RESPONSE, HTML_MIN_AVAIL_SIZE);
  }
  if(enabled_schemes[PDF_GET]){
    init_PDF_payload_pool(payloads, HTTP_MSG_BUF_SIZE, TYPE_HTTP_RESPONSE, PDF_MIN_AVAIL_SIZE);
  }
  if(enabled_schemes[SWF_GET]){
    init_SWF_payload_pool(payloads, HTTP_MSG_BUF_SIZE, TYPE_HTTP_RESPONSE, 0);
  }

  if(enabled_schemes[JPEG_POST] || enabled_schemes[JPEG_GET]){
    payloads.pool = load_images(imagedir);  
  }

  if(enabled_schemes[PDF_POST]){
    payloads.pool_pdf = load_pdfs(pdfdir);  
  }
}


rcode_t
schemes_gen_uri_field (char* uri, size_t uri_sz, char* data, size_t& datalen)
{
  size_t so_far = 0;
  int coin_toss;    


  memset(uri, 0, uri_sz);
  strcat(uri, "GET /");
  so_far = 5;

  while (datalen > 0 && uri_sz - so_far >= 7) {
    unsigned int r = rand() % 4;

    if (r == 1) {
      r = rand() % 46;

      if (r < 20)
        uri[so_far++] = 'g' + r;
      else
        uri[so_far++] = 'A' + r - 20;
    }
    else {
      uri[so_far++] = data[0];
      data++;
      datalen--;
    }

    r = rand() % 8;

    if (r == 0 && datalen > 0)
      uri[so_far++] = '/';

    if (r == 2 && datalen > 0)
      uri[so_far++] = '_';
  }

  if (uri_sz - so_far < 7) {
    log_warn("too small: %" PriSize_t " vs %" PriSize_t, so_far, uri_sz);
    goto err;
  }

 retry:
  coin_toss  = rand() % 8;

  switch(coin_toss){
  case 0:
    if(enabled_schemes[SWF_GET] && schemes_is_usable(HTTP_CONTENT_SWF)){
      if (memncpy(uri+so_far, uri_sz-so_far, ".swf ", 6) != RCODE_OK)
	goto err;
      break;
    }
  case 1:
    if(enabled_schemes[HTML_GET] &&  schemes_is_usable(HTTP_CONTENT_HTML)) {
      if (memncpy(uri+so_far, uri_sz-so_far, ".htm ", 6) != RCODE_OK)
	goto err;
      break;
    }
  case 2:
    if(enabled_schemes[HTML_GET] && schemes_is_usable(HTTP_CONTENT_HTML)) {
      if (memncpy(uri+so_far, uri_sz-so_far, ".html ", 7) != RCODE_OK)
	goto err;
      break;
    }
  case 3:
    if(enabled_schemes[JS_GET] && schemes_is_usable(HTTP_CONTENT_JAVASCRIPT)){
      if (memncpy(uri+so_far, uri_sz-so_far, ".js ", 5) != RCODE_OK)
	goto err;
      break;
    }
  case 4:
    if(enabled_schemes[PDF_GET] && schemes_is_usable(HTTP_CONTENT_PDF)){
      if (memncpy(uri+so_far, uri_sz-so_far, ".pdf ", 6) != RCODE_OK)
	goto err;
      break;
    }
  case 5:
    if (enabled_schemes[JSON_GET] && schemes_is_usable(HTTP_CONTENT_JSON)) {
      if (memncpy(uri+so_far, uri_sz-so_far, ".json ", 7) != RCODE_OK)
	goto err;
      break;
    }
  case 6:
    if (enabled_schemes[JPEG_GET] && schemes_is_usable(HTTP_CONTENT_JPEG)) {
      if (memncpy(uri+so_far, uri_sz-so_far, ".jpg ", 6) != RCODE_OK)
	goto err;
      break;
    }
  case 7:
    if (enabled_schemes[RAW_GET] && schemes_is_usable(HTTP_CONTENT_RAW)) {
      if (memncpy(uri+so_far, uri_sz-so_far, ".exe ", 6) != RCODE_OK)
	goto err;
      break;
    }
  default:
    goto retry;
  }

  datalen = strlen(uri);
  return RCODE_OK;

 err:
  return RCODE_ERROR;  
}


int
schemes_gen_post_request_path (payloads& p, char** uri)
{
  int bufsize = 4096, counter = 0, retval = 0;
  char* buf = (char*) xmalloc(bufsize), *path = NULL;
  size_t payload_len = 0;

  // retry up to 10 times
  if((buf == NULL) || (uri == NULL)){ goto clean_up; }

  while (!payload_len &&  (counter++ < 10)) {
    if (find_client_payload(p, buf, bufsize, TYPE_HTTP_REQUEST, payload_len) != RCODE_OK)
      continue;
  }

  buf[payload_len] = '\0';
  
  if(payload_len > 0){
    char *start = strchr(buf, ' ');     //drop the method
    if(start == NULL){ goto clean_up; }
    start = start + 1;
    char *stop =  strchr(start, ' ');   //chop before the protocol
    if(stop == NULL){ goto clean_up; }
    stop[0] = '\0';
    stop = strchr(start, '?');          //chop any query string
    if(stop != NULL){
      stop[0] = '\0';
    }
    stop = strchr(start, ';');          //chop any query string
    if(stop != NULL){
      stop[0] = '\0';
    }
    stop = strchr(start, '.');           //chop any extension
    if(stop != NULL){
      stop[0] = '\0';
    }
    //log_warn("got a request: %s", start);
    path = xstrdup(start);
  } else {
    path = xstrdup("/enlighten/calais.asmx");
  }
  *uri = path;
  retval = strlen(path);
  
 clean_up:
  free(buf);
  return retval;
}


void schemes_dump(FILE* stream){
  int index;

  assert(stream != NULL);

  for(index = 0; index < STEG_TRANSPORT_SCHEMES_MAX; index++){
    fprintf(stream, "%s: %d\n", schemes_to_string(index), enabled_schemes[index]);
  }

}
