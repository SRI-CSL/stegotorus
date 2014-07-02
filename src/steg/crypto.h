/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */




#ifndef _CRYPTO_H
#define _CRYPTO_H
#include <openssl/evp.h>

#include "types.h"


uchar* defiant_pwd_encrypt(const char* password, const uchar* plaintext, size_t plaintextlen,  size_t *output_len);
uchar* defiant_pwd_decrypt(const char* password, const uchar* data, size_t datalen, size_t *output_len);

  
  
#endif /* _CRYPTO_H */
