#include "jel_knobs.h"


void init_jel_knobs(jel_knobs_t& knobs){
  knobs.embed_length  = true;
  knobs.use_ecc       = true;
  knobs.ecc_blocklen  = 20;     
  knobs.freq_pool     = 16;
  knobs.quality_out   = 75;
  knobs.random_seed   = 0;
}

using std::to_string;

string jel_knobs_info_string(jel_knobs_t* knobs){
  string buffer;
  buffer.append("embed_length=\t").append(to_string(knobs->embed_length)).append("\n");
  buffer.append("use_ecc=\t").append(to_string(knobs->use_ecc)).append("\n");
  buffer.append("ecc_blocklen=\t").append(to_string(knobs->ecc_blocklen)).append("\n");
  buffer.append("freq_pool=\t").append(to_string(knobs->freq_pool)).append("\n");
  buffer.append("quality_out=\t").append(to_string(knobs->quality_out)).append("\n");
  buffer.append("random_seed=\t").append(to_string(knobs->random_seed)).append("\n");
  return buffer;
}
