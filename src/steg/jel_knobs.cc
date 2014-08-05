#include "jel_knobs.h"


void init_jel_knobs(jel_knobs_t& knobs){
  knobs.embed_length  = true;
  knobs.ecc_blocklen  = 20;     
  knobs.freq_pool     = 16;
  knobs.quality_out   = 75;
  knobs.random_seed   = 0;
}


