#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "util.h"
#include "oshacks.h"
#include "crypto.h"
#include "strncasestr.h"



#define AES_BLOCK_LENGTH 16

/* easy to vary the cipher; not sure if this makes anything more robust though */
static const EVP_CIPHER* 
defiant_cipher (int i)
{
  switch(i){
  case 0: return EVP_aes_256_cbc();
  case 1: return EVP_bf_cbc();
  case 2: return EVP_cast5_cbc();
  default: return EVP_aes_256_cbc();
  }
}


typedef struct _bundle {
  int cipher;
  uchar key[EVP_MAX_KEY_LENGTH];
  uchar iv[EVP_MAX_IV_LENGTH];
  EVP_CIPHER_CTX context;
} bundle;


static uchar* defiant_encrypt(bundle* bag, const uchar* plaintext, size_t plaintextlen, size_t *output_len);
static uchar* defiant_decrypt(bundle* bag, const uchar* data, size_t datalen, size_t *output_len);

static uchar* decrypt_aux(EVP_CIPHER_CTX *context, const uchar* input, size_t input_len, size_t *output_len);
static uchar* encrypt_aux(EVP_CIPHER_CTX *context, const uchar* input, size_t input_len, size_t *output_len);



uchar* 
defiant_pwd_encrypt (const char* password, const uchar* plaintext, size_t plaintextlen, size_t *output_len)
{
  bundle bag;
  rcode_t  retcode;
  size_t password_length = strlen(password);
  bag.cipher = 0;
  password_length = (password_length > EVP_MAX_KEY_LENGTH ? EVP_MAX_KEY_LENGTH : password_length); 
  memset(bag.key, 0, EVP_MAX_KEY_LENGTH);
  retcode = memncpy(bag.key, EVP_MAX_KEY_LENGTH, password, password_length);
  assert(retcode == RCODE_OK);
  memset(bag.iv, 0, EVP_MAX_IV_LENGTH);
  /* could improvise with the iv too */
  return defiant_encrypt(&bag, plaintext, plaintextlen, output_len);
}

uchar* 
defiant_pwd_decrypt (const char* password, const uchar* data, size_t datalen, size_t *output_len)
{
  bundle bag;
  rcode_t retcode;
  size_t password_length = strlen(password);
  bag.cipher = 0;
  password_length = (password_length > EVP_MAX_KEY_LENGTH ? EVP_MAX_KEY_LENGTH : password_length); 
  memset(bag.key, 0, EVP_MAX_KEY_LENGTH);
  retcode = memncpy(bag.key, EVP_MAX_KEY_LENGTH, password, password_length);
  assert(retcode == RCODE_OK);
  memset(bag.iv, 0, EVP_MAX_IV_LENGTH);
  /* could improvise with the iv too */
  return defiant_decrypt(&bag, data, datalen, output_len);
}

uchar* 
defiant_encrypt (bundle* bag, const uchar* plaintext, size_t plaintextlen, size_t *output_len)
{
  uchar* retval = NULL;
  EVP_EncryptInit(&(bag->context), defiant_cipher(bag->cipher), bag->key, bag->iv);
  retval = encrypt_aux(&(bag->context), (uchar*)plaintext, plaintextlen, output_len);
  EVP_CIPHER_CTX_cleanup(&(bag->context));
  return retval;
}

uchar* 
defiant_decrypt (bundle* bag, const uchar* data, size_t datalen, size_t *output_len)
{
  uchar* retval = NULL;
  EVP_DecryptInit(&(bag->context), defiant_cipher(bag->cipher), bag->key, bag->iv);
  retval = decrypt_aux(&(bag->context), data, datalen, output_len);
  EVP_CIPHER_CTX_cleanup(&(bag->context));
  return retval;
}


uchar* 
encrypt_aux (EVP_CIPHER_CTX *context, const uchar* input, size_t input_len, size_t *output_len)
{
  uchar* output = (uchar*)calloc(input_len + EVP_CIPHER_CTX_block_size(context), sizeof(uchar));
  size_t i;
  size_t offset = 0, remainder = input_len % AES_BLOCK_LENGTH;
  int incr;

  for(i = 0; i < input_len / AES_BLOCK_LENGTH; i++){
    if(EVP_EncryptUpdate(context, &output[offset], &incr, &input[offset], AES_BLOCK_LENGTH)){
      offset +=  incr;
    } 
  }
  
  if(remainder){
    if(EVP_EncryptUpdate(context, &output[offset], &incr, &input[offset], remainder)){
      offset +=  incr;
    } 
  }
  
  EVP_EncryptFinal(context, &output[offset], &incr);
  offset +=  incr;

  
  *output_len = offset;
  return output;
}

uchar* 
decrypt_aux (EVP_CIPHER_CTX *context, const uchar* input, size_t input_len, size_t *output_len)
{
  uchar* output = (uchar*)calloc(input_len + EVP_CIPHER_CTX_block_size(context) + 1, sizeof(uchar));
  int offset, dangle;
  EVP_DecryptUpdate(context, output, &offset, input, input_len);
  if(!offset){
    free(output);
    *output_len = 0;
    return NULL;
  }
  if(EVP_DecryptFinal(context, &output[offset], &dangle) == 0){
    log_warn("decrypt_aux: Padding wrong :-(  input length = %" PriSize_t, input_len);
    free(output);
    *output_len = 0;
    return NULL;
  } else {
    offset += dangle;
  }
  output[offset] = '\0';
  *output_len = offset;
  return output;
}





