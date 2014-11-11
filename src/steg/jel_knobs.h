#ifndef _JEL_KNOBS_H
#define _JEL_KNOBS_H

#include <stddef.h>
#include <stdint.h>
#include <string>

using std::string;

typedef struct jel_knobs {
  bool    embed_length;     /* embed the message length as part of the message   default = true  */
  bool    use_ecc;          /* use error correction                              default = true  */
  int32_t ecc_blocklen;     /* ecc block length                                  default = 20    */
  int32_t freq_pool;        /* size of the frquency pool                         default = 16    */
  int32_t quality_out;      /* the quality of the resulting jpeg                 default = 75?   */
  int32_t random_seed;      /* the seed to random choice of 4 freqs from the freq_pool           */
} jel_knobs_t;

void init_jel_knobs(jel_knobs_t& knobs);

string jel_knobs_info_string(jel_knobs_t* knobs);



#endif
