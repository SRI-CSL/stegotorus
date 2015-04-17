/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "payloads.h"
#include "jsonSteg.h"
#include "base64.h"
#include "b64cookies.h"
#include "connections.h"
#include "shared.h"
#include "headers.h"
#include "schemes.h"
#include "strncasestr.h"
#include "protocol.h"
#include "crypto.h"
#include "oshacks.h"


#include <ctype.h>
#include <string>
#include <vector>
#include <math.h>

#include <event2/buffer.h>

#include <jansson.h>

#define JSON_PAYLOAD_PLACEHOLDER  "%k"

/* number of bytes per placeholder/object   */
#define JSON_PAYLOAD_BYTES_PER_PLACEHOLDER  64


#define DEBUG_FORMATS 0

/* 
   We use the following convention within formats (could easily be extended over time):
   
   %d   random int
   %s   random string
   %k   the payload

*/

/*
 * a payload will be a homogeneous array of these kinds of objects (homogeneous == one format per array), the
 * formats are currently randomly generated, one size fits all. Though it might be better to adapt the
 * format used according to the method (posts vs gets).
 *
 *
 */

static std::string
random_field(char c);

static std::string
random_string(int minlength, int maxlength);

static std::string
random_integer(int maxdigits);

static std::string
random_format();

static int
get_placeholder_count(const char *format, size_t format_length);

static size_t
construct_json_body(char* format, size_t format_length, char* data,  size_t datalen, char**bodyp, int zipped);

static size_t
deconstruct_json_body(char* format, size_t format_length, char *body, size_t body_len, char** datap, int zipped);

static size_t
construct_json_headers(int method, const char *path, const char* host, const char* cookie, size_t body_length, char* headers, int zipped);

static char*
construct_json_format(int method, size_t payload);

static char*
construct_json_cookie(char *format, size_t format_length, const char *secret);

static char*
deconstruct_json_cookie(char *cookie, const char *secret);

static char*
construct_json_cookie_aux(char *format, size_t format_length, const char *secret, size_t *clenp);

static char*
deconstruct_json_cookie_aux(char *cookie, size_t cookie_length, const char *secret, size_t *flenp);

static size_t
construct_json_body_unzipped(char* format, size_t format_length, char* data,  size_t datalen, char**bodyp);

static size_t 
deconstruct_json_body_unzipped(char* format, size_t format_length, char *body, char** datap);



/*
 *
 *  Could pay attention to the method and the payload size.
 *  Small payload  (i.e. less than JSON_PAYLOAD_BYTES_PER_PLACEHOLDER) might be best to force it into one slot.
 *  Large payload might be best to increase the number of slots. 
 *  Need to be able to test this with respect to performance to warrant the addtional complexity.
 *
 *  Also note that my guess is long arrays of little objects in POSTs are rare, less so in GETs.
 *  
 */
char*
construct_json_format(int  /* method */, size_t /* payload */)
{
  char* retval = NULL;
  std::string rformat = random_format();
  const char* cf = rformat.c_str();
  retval = xstrdup(cf);
  return retval;
}

int
get_placeholder_count(const char *format, size_t format_length)
{
  int count = 0;
  size_t start_length = format_length;
  const char* start = format;
  
  while((start = strnstr(start, JSON_PAYLOAD_PLACEHOLDER, start_length)) != NULL){
    size_t offset;
    count++;
    start += strlen(JSON_PAYLOAD_PLACEHOLDER);
    offset = start - format;
    start_length = format_length - offset;
  }
  return count;
}

char*
construct_json_cookie(char *format, size_t format_length, const char *secret)
{
  size_t cookie_length = 0;
  char* cookie = construct_json_cookie_aux(format, format_length, secret, &cookie_length);

  if(DEBUG_FORMATS){

    if(cookie){
      log_warn(">format = %s\nformat_length=%" PriSize_t "\nCookie: %s", format, format_length, cookie);
    } else {
      log_warn("Cookie: NULL");
    }

  }
  return cookie;
}

char*
deconstruct_json_cookie(char *cookie, const char *secret)
{
  size_t format_length = 0, cookie_length = strlen(cookie);
  char* format = deconstruct_json_cookie_aux(cookie, cookie_length, secret, &format_length);
  if(DEBUG_FORMATS){

    if(format){
      log_warn("<cookie = %s>", cookie);
      log_warn("<cookie_length=%" PriSize_t ">", cookie_length);
      log_warn("<format:%s>", format);
    } else {
      log_warn("Format: NULL");
    }
    
  }
  return format;
}



char*
construct_json_cookie_aux(char *format, size_t format_length, const char * secret, size_t *clenp)
{
  char  *cookie = NULL;
  size_t data_length = 0;
  uchar* data  = defiant_pwd_encrypt(secret, (uchar *)format, format_length, &data_length);
  size_t cookie_length;
  
  if (encode_cookie((char*)data, data_length, &cookie, cookie_length) != RCODE_OK)
    goto clean_up;
  
  *clenp = cookie_length;

 clean_up:
  free(data);
  return cookie;
}

char*
deconstruct_json_cookie_aux(char *cookie, size_t cookie_length, const char * secret, size_t *flenp)
{
  uchar* data = (uchar*)xmalloc(2*cookie_length);
  size_t ptext_length = 0;
  size_t data_length;
  char* ptext = NULL;

  if (decode_cookie(cookie, cookie_length, (char*)data, data_length) != RCODE_OK)
    goto clean_up;
  
  
  ptext = (char *)defiant_pwd_decrypt(secret, data, data_length, &ptext_length);
  *flenp = ptext_length;
  
 clean_up:
  free(data);
  return ptext;
}

enum kinds { K_INT = 0, K_STRING, K_DATA }; //  %d  %s  %k

/* generates a randomish format */
std::string
random_format()
{
  std::string retval = "{";
  int fields[3] = { 0, 0, 0 };   
  int empty = 1;
  std::string field;
  
  while((fields[K_INT] == 0) || (fields[K_STRING] == 0) || (fields[K_DATA] == 0)){
    int toss = rand() % 3;
    
    if((toss == K_STRING) &&  fields[K_STRING] != 0){ continue; }   //too much stuff considered bloat
    
    if(fields[toss] > 2){ continue;  }                              //too much padding considered harmful

    if(empty){
      empty = 0;
    } else {
      retval.append(",");
    }
    
    switch(toss){
    case K_INT: {
      field = random_field('d');
      fields[K_INT]++;
      retval.append(field);
      break;
    }
    case K_STRING: {
      field = random_field('s');
      fields[K_STRING]++;
      retval.append(field);
      break;
    }
    case K_DATA: {
      field = random_field('k');
      fields[K_DATA]++;
      retval.append(field);
      break;
    }
    default:
      break;
    }
  }
  retval.append("}");
  return retval;
}

std::string
random_field(char c)
{
  std::string retval;
  std::string fieldname = random_string(5, 10);

  retval.append("\"").append(fieldname).append("\"");
  
  if(c == 'd'){
    retval.append(":%");
    retval += c;
  } else {
    retval.append(":\"%");
    retval += c;
    retval.append("\"");
  }
  return retval;
}

std::string
random_string(int minlength, int maxlength)
{
  std::string retval;
  int length = minlength + (rand() % (maxlength - minlength)) + 1;
  int c, offset = 0;
  
  while (offset < length) {
    c = rand() % (127 - 33) + 33;

    if(!isalnum(c)){
      continue;
    } else {
      retval += (char)c;
      offset++;
    }
    
  }
  return retval;
}

std::string
random_integer(int maxdigits)
{
  std::string retval;
  int digits = maxdigits + 1, moduli = pow(10, digits);
  int r = rand() % moduli;
  char ibuff[digits + 1];
  sprintf(ibuff, "%d", r);
  retval.append(ibuff);
  return retval;
}




/* note that we should only do this once, not for every object. also note we are assuming just one %k field */
std::string
get_fieldname(const char *format, size_t format_length)
{
  std::string retval;
  int success = 0, error = 0;
  char *fmt = xstrdup(format);
  char placeholder[] = JSON_PAYLOAD_PLACEHOLDER;
  char *start;
  char *end = strnstr(fmt, placeholder, format_length);
  
  if(end == NULL){ error = 1; goto cleanup; }

  *end = '\0';
  end = strrchr(fmt, ':');
  
  if(end == NULL){ error = 2; goto cleanup; }
  
  *end = '\0';
  //at this point we look for either a "," or if none, then the starting "{"
  start = strrchr(fmt, ',');
  
  if(start == NULL){
    /* better be the first field in the format then */
     start = strrchr(fmt, '{');
  }
  
  if(start == NULL){ error = 3; goto cleanup; }
  
  for(size_t index = 0; index < strlen(start); index++){
    char c = start[index];

    if(isalnum(c)){
      retval += c;
    }

  }
  success = 1;

 cleanup:
  free(fmt);
  log_debug("fieldname: %d %d %s", success, error, retval.c_str());
  return retval;
}

std::vector<std::string>
get_fieldnames(const char *format, size_t format_length)
{
  std::vector<std::string> retval;
  const char* start = format;
  size_t start_length = format_length;
  size_t offset;

  while(1){
    std::string field = get_fieldname(start, format_length);

    if(field.length() == 0){ break; }

    retval.push_back(field);
    start = strnstr(start, JSON_PAYLOAD_PLACEHOLDER, start_length);

    if(start != NULL){
      start += strlen(JSON_PAYLOAD_PLACEHOLDER);
      offset = start - format;
      start_length = format_length - offset;
    } else {
      /* shouldn't happen */
      break;
    }
    
  }
  return retval;
}



std::string
instantiate_json_format(const char *format, size_t format_length, char* data, size_t datalen, size_t offset)
{
  size_t format_offset = 0;
  size_t data_offset = offset;
  std::string retval;
  char c, t;
  
  while((format_offset < format_length) && (c = format[format_offset]) != '\0'){

    if(c == '%'){
      t = format[++format_offset];

      switch(t){
      case 'd': {
        std::string ri = random_integer(4);
        retval.append(ri);
        break;
      }
      case 's': {
        std::string rs = random_string(4, 10);
        retval.append(rs);
        break;
      }
      case 'k': {
        int count = 0;

        while((data_offset < datalen) && (count < JSON_PAYLOAD_BYTES_PER_PLACEHOLDER)){
          retval += data[data_offset++];
          count++;
        }
        break;
      }
      default: {
        log_warn("error: unknown format placeholder: %c", t);
        retval.append("mystery");
        break;
      }
      }
    } else {
      retval += c;
    }
    format_offset++;
  }
  return retval;
}

std::string
extract_json_data(json_t * dataobj, const char *fieldname)
{
  std::string retval;

  if(!json_is_object(dataobj)){
    log_warn("error: json data is not an object");
  } else {
    json_t *message = json_object_get(dataobj, fieldname);

    if(!json_is_string(message)){
      log_warn("error: message is not a string");
    } else {
      retval.append(json_string_value(message));
    }
  }
  return retval;
}


size_t
construct_json_body_unzipped(char* format, size_t format_length, char* data,  size_t datalen , char** bodyp )
{
  size_t body_length = 0;
  size_t offset = 0;
  int empty = 1, placeholder_count = 0, bytes_per_object = 0;
  char* body = NULL;
  std::string data_buffer;
  
  //algorithm:
  // 
  // given a random json format; figure out how many slots per object we have

  placeholder_count = get_placeholder_count(format, format_length);

  if(placeholder_count == 0){ return 0; }
  
  // compute the number of objects needed in the array
  
  bytes_per_object = JSON_PAYLOAD_BYTES_PER_PLACEHOLDER * placeholder_count;
  
  int obj_count = datalen / bytes_per_object;

  /* need one for any dregs */
  if(datalen % bytes_per_object){
    obj_count++;
  }

  data_buffer.append("[");
  
  // for each required object construct its instantiation and add it to the array
  for(int i = 0; i < obj_count; i++){
    std::string obj = instantiate_json_format(format, format_length, data, datalen, offset);

    if(!empty){
      data_buffer.append(",");
    } else {
      empty = 0;
    }
    
    data_buffer.append(obj);
    offset += bytes_per_object;
  }

   data_buffer.append("]");
   
   // "return" the constructed array.
   body_length = data_buffer.size();   
   body = xstrdup(data_buffer.c_str());
   
   if(body != NULL){
     *bodyp = body;
   } else {
     body_length = 0;
   }

   return body_length;
}

size_t
construct_json_body(char* format, size_t format_length, char* data,  size_t datalen, char**bodyp, int zipped)
{
  size_t body_length = 0;
  char *body = NULL;

  if(bodyp != NULL){
    body_length = construct_json_body_unzipped(format, format_length, data, datalen, &body);
    if(zipped){
      //zip here
      char* zbody = NULL;
      size_t zbody_len = 0;
      int cval = compressor(body,  body_length, &zbody, &zbody_len);

      if(cval == 0){
        free(body);
        body = zbody;
        body_length = zbody_len;
      } else {
        log_warn("construct_json_body: compression (of %" PriSize_t " bytes) went awry: %d", datalen, cval);
      }
    }
    *bodyp = body;
  }
  return body_length;
}



size_t
construct_json_headers(int method, const char* path, const char* host, const char* cookie, size_t body_length, char* headers, int zipped)
{
  size_t headers_length = MAX_HEADERS_SIZE;

  if(method == HTTP_GET){
    if (gen_response_header(JSON_CONTENT_TYPE, cookie, zipped, body_length, headers, headers_length, headers_length) != RCODE_OK)
      goto err;
  } else if(method == HTTP_POST){
    if (gen_post_header(JSON_CONTENT_TYPE, path, host, cookie, zipped, body_length, headers, headers_length, headers_length) != RCODE_OK)
      goto err;
  } else {
    log_warn("Bad method %d to construct_json_headers (HTTP_GET = %d, HTTP_POST = %d)", method, HTTP_GET, HTTP_POST);
  }
  
  return headers_length;

 err:
  return 0;
}



size_t
deconstruct_json_body_unzipped(char* format, size_t format_length, char * body, char** datap)
{
  size_t data_length = 0;
  size_t array_length = 0;
  std::string data_buffer;
  char *data = NULL;
  json_t *root = NULL;
  json_error_t error;

  //algorithm:
  //step 1: get the data bearing fields from the format
  std::vector<std::string>  fieldnames = get_fieldnames(format, format_length);

  if(fieldnames.size() == 0){
    log_warn("error: format had no payload placeholder");
    goto clean_up;
  }
  
  //step 2:  parse the json into an array of objects
  root = json_loads(body, 0, &error);

  if(!json_is_array(root)){
    log_warn("error: root is not an array");
    goto clean_up;
  }
  
  array_length = json_array_size(root);
  
  if(array_length == 0){
    log_warn("error: root is zero length array");
    goto clean_up;
  } 

  //step 3:  unpack each member of the array according to that format and add it to the data_buffer
  for(size_t i = 0; i < array_length; i++){
    json_t *data = json_array_get(root, i);
    for(size_t j = 0; j < fieldnames.size(); j++){
      data_buffer.append(extract_json_data(data, fieldnames[j].c_str()));
    }
  }

  //step 4:  prep the return value
  data_length = data_buffer.size();

  //step 5: "return" the data_buffer
  data = xstrdup(data_buffer.c_str());

  if(data != NULL){
    *datap = data;
  } else {
    data_length = 0;
  }

 clean_up:
  json_decref(root);
  return data_length;
}

size_t 
deconstruct_json_body(char* format, size_t format_length, char *body, size_t bodylen, char** datap, int zipped)
{
  //coverity thinks this can happen; i don't.
  if(format == NULL){
    return 0;
  }
  
  if(zipped){
    //unzip here
    char *decompressed_body = NULL;
    size_t decompressed_bodylen = 0;
    int dval = decompressor(body,  bodylen, &decompressed_body, &decompressed_bodylen);
    
    if(dval == 0){
      int retval = deconstruct_json_body_unzipped(format, format_length, decompressed_body,  datap);
      free(decompressed_body);
      return retval;
    } else {
      log_warn("deconstruct_json_body: decompression went awry");
      return 0;
    }
    
  } else {
    return deconstruct_json_body_unzipped(format, format_length, body,  datap);
  }
  
  return 0;
}

transmit_t
http_server_JSON_transmit (http_steg_t * s,  struct evbuffer *source)
{
  transmit_t retval = TRANSMIT_GOOD;
  const char *secret = s->config->shared_secret;
  conn_t *conn = s->conn;
  char* data = NULL, *body = NULL, *format = NULL, *cookie = NULL, *headers = NULL;
  size_t format_length;
  struct evbuffer *dest;
  size_t source_length;
  /* buffer to hold our base64 payload */
  size_t data_length = 0;
  size_t body_length = 0, headers_length = 0;
  
  if((source == NULL) || (conn == NULL)){
    log_warn("bad args");
    retval = NOT_TRANSMITTED;
    goto clean_up;
  } 

  source_length = evbuffer_get_length(source);
  headers = (char *)xzalloc(MAX_HEADERS_SIZE);
  
  if(headers == NULL){
    log_warn("header allocation failed.");
    retval = NOT_TRANSMITTED;
    goto clean_up;
  }
  
  log_debug("source_length = %d", (int) source_length);
  
  if (source2hex(source, source_length, &data, data_length) != RCODE_OK) {
    log_warn("source2hex returned negative value\n");
    retval = NOT_TRANSMITTED;
    goto clean_up;
  }
  
  /* need to make the body of the response; then make the headers  */
  format = construct_json_format(HTTP_GET, data_length);
  format_length =  (format != NULL) ? strlen(format) : 0;  
  cookie = construct_json_cookie(format, format_length, secret);
  
  //log_warn("<cookie = %s>", cookie);
  body_length = construct_json_body(format, format_length, data, data_length, &body, s->accepts_gzip);
  
  //log_warn("sending gzipped JSON = %d", s->accepts_gzip);
  
  if(body_length == 0){
    log_warn("construct_json_body failed.");
    retval = NOT_TRANSMITTED;
    goto clean_up;
  }

  headers_length = construct_json_headers(HTTP_GET, NULL, NULL, cookie, body_length, headers, s->accepts_gzip);
  
  if(headers_length == 0){
    log_warn("construct_json_headers failed.");
    retval = NOT_TRANSMITTED;
    goto clean_up;
  }
  
  //log_warn("json transmit headers = <headers>\n%s</headers>", headers);
  dest = conn->outbound();
  
  if (evbuffer_add(dest, headers, headers_length)  == -1) {
    log_warn("evbuffer_add() fails for headers");
    retval = NOT_TRANSMITTED;
    goto clean_up;
  }
  
  if (evbuffer_add(dest, body, body_length)  == -1) {
    log_warn("evbuffer_add() fails for body");
    retval = NOT_TRANSMITTED;
    goto clean_up;
  }
    
  evbuffer_drain(source, source_length);
  
  if(SCHEMES_PROFILING){
    profile_data("JSON", headers_length, body_length, source_length);
  }
  
 clean_up:
  if(headers != NULL){ free(headers); }
  if(format != NULL){ free(format); }
  if(cookie != NULL){ free(cookie); }
  if(data != NULL){ free(data); }
  if(body != NULL){ free(body); }
  return retval;
}

recv_t
http_client_JSON_receive (http_steg_t *s, struct evbuffer *dest, char* headers, size_t headers_length, char* response, size_t response_length)
{
  const char *secret = s->config->shared_secret;
  recv_t retval = RECV_BAD;
  size_t data_length = 0;
  char *body = NULL, *data = NULL, *format = NULL, *cookie = NULL;
  size_t cookie_length;
  size_t format_length;


  if(!(headers_length < response_length)){
    log_warn("http_client_JSON_receive: headers_length = %" PriSize_t "\n response_length = %" PriSize_t, headers_length, response_length);
  }

  assert(headers_length < response_length);

  if (get_cookie(headers, headers_length, &cookie, cookie_length) == RCODE_OK && cookie_length > 0) {
    format = deconstruct_json_cookie(cookie, secret);
    format_length = (format != NULL) ? (int)strlen(format) : 0;
  } 
  else {
    log_warn("no cookie found");
    retval = RECV_BAD;
    goto  clean_up;
  }
  
  //log_warn("<cookie = %s>", cookie);
  
  if(format == NULL){
    log_warn("no cookie didn't decode to a format");
    retval = RECV_BAD;
    goto  clean_up;
  }
  
  body = &response[headers_length];
  data_length = deconstruct_json_body(format, format_length, body, response_length - headers_length, &data,  s->is_gzipped);
  retval = hex2dest(dest,  data_length, data);

 clean_up:
  if(cookie != NULL){ free(cookie); }
  if(format != NULL){ free(format); }
  if(data != NULL){ free(data); }
  return retval;
}
  

transmit_t
http_client_JSON_post_transmit (http_steg_t *s, struct evbuffer *source, conn_t *conn)
{
  transmit_t retval = NOT_TRANSMITTED;
  struct evbuffer *dest = conn->outbound();
  size_t source_length = evbuffer_get_length(source);
  unsigned int body_length = 0, headers_length = 0;
  char *data = NULL, *body = NULL, *path = NULL, *format = NULL, *cookie = NULL, *headers = NULL;
  size_t datalen;
  const char *secret = s->config->shared_secret;
  const char *hostname = s->config->hostname;
  size_t format_length = 0;

  //posts shouldn't be gzipped, since the client can't know that the server supports it.
  bool json_zipping = false;
  

  if (source2hex(source, source_length, &data, datalen) != RCODE_OK) {
    log_warn("extracting hex to send failed");
    goto clean_up;
  }

  headers = (char *)xzalloc(MAX_HEADERS_SIZE);

  if(headers == NULL){
    log_warn("header allocation failed.");
    retval = NOT_TRANSMITTED;
    goto clean_up;
  }
  
  
  format = construct_json_format(HTTP_POST, datalen);
  format_length = (format != NULL) ? (int)strlen(format) : 0;
  cookie = construct_json_cookie(format, format_length, secret);
  body_length = construct_json_body(format, format_length, data,  datalen, &body, json_zipping);

  if(body_length == 0){
    log_warn("construct_json_body failed.");
    goto clean_up;
  }
  
  //log_warn("http_client_JSON_post_transmit\n<data>\n%d:%s\n</data>\n<cookie>\n%d:%s\n</cookie>\n<body>\n%d:%s\n</body>", datalen, data, (int)strlen(cookie), cookie, (int)strlen(body), body);

  schemes_gen_post_request_path(s->config->pl, &path);
  headers_length = construct_json_headers(HTTP_POST, path, hostname, cookie, body_length, headers, json_zipping);

  if(headers_length == 0){
    log_warn("construct_json_headers failed.");
    goto clean_up;
  }
  
  //log_warn("post headers = <headers>\n%s</headers>", headers);

  
  if (evbuffer_add(dest, headers, headers_length) == -1) {
    log_warn("evbuffer_add() fails for headers");
    goto clean_up;
  }
  
  if (evbuffer_add(dest, body, body_length) == -1) {
    log_warn("evbuffer_add() fails for body");
    goto clean_up;
  }
  
  evbuffer_drain(source, source_length);

  if(!s->persist_mode){
    conn->cease_transmission();
  } else {
    conn_do_flush(conn);
  }
  
  s->type = HTTP_CONTENT_JSON;
  s->have_transmitted = true;
  s->have_received = false;
  retval = TRANSMIT_GOOD;

  if(SCHEMES_PROFILING){
    profile_data("JSON", headers_length, body_length, source_length);
  }
  
 clean_up:
  if(headers != NULL)free(headers);
  if(format != NULL)free(format);
  if(cookie != NULL)free(cookie);
  if(data != NULL)free(data);
  if(body != NULL){ free(body); }
  if(path != NULL){ free(path); }
  return retval;

}

recv_t
http_server_JSON_post_receive(http_steg_t * s, struct evbuffer *dest, char* headers, size_t headers_length, char* request, size_t request_length)
{
  recv_t retval = RECV_BAD;
  /* JSON POST MODE */
  char *data = NULL, *body = NULL, *format = NULL, *cookie = NULL; 
  size_t data_length = 0; 
  size_t cookie_length = 0, format_length = 0;
  const char *secret = s->config->shared_secret;
  
  /* posts shouldn't be gzipped, since the client can't know in advance that the server supports it. */
  bool json_zipping = false;

  if(!(headers_length < request_length)){
    log_warn("http_server_JSON_post_receive: headers_length = %" PriSize_t "\n request_length = %" PriSize_t, headers_length, request_length);
  }
  assert(headers_length < request_length);

  /* log_warn("post headers = <headers>\n%s</headers>\n cookie_length = %" PriSize_t, headers, cookie_length); */
  
  if(get_cookie(headers, headers_length, &cookie, cookie_length) == RCODE_OK  && cookie_length > 0) {
    if(cookie == NULL){ /* coverity is a bit thick. */
      log_warn("cookie NULL");
      return RECV_BAD;
    }
    format = deconstruct_json_cookie(cookie, secret);
    if (format == NULL) {
      log_warn("invalid cookie received");
      if(cookie != NULL) free(cookie);
      return RECV_BAD;
    }
    format_length = (int)strlen(format);
  }
  
  body = &request[headers_length];
  
  data_length = deconstruct_json_body(format, format_length, body, request_length - headers_length, &data, json_zipping);
  
  /* log_warn("\n<data>\n%" PriSize_t ":%s\n</data>\n<cookie>\n%" PriSize_t ":%s\n</cookie>\n<body>\n%" PriSize_t ":%s\n</body>", data_length, data, strlen(cookie), cookie, strlen(body), body); */

  retval = hex2dest(dest,  data_length, data);
  
  if(cookie != NULL) free(cookie);
  if(format != NULL) free(format);
  if(data != NULL) free(data);
  return retval;
}
