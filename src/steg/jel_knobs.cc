#include "jel_knobs.h"

#include <sstream>

void init_jel_knobs(jel_knobs_t& knobs){
  knobs.embed_length  = true;
  knobs.use_ecc       = true;
  knobs.ecc_blocklen  = 20;     
  knobs.freq_pool     = 16;
  knobs.quality_out   = 75;
  knobs.random_seed   = 0;
}


string jel_knobs_info_string(jel_knobs_t* knobs){
  std::stringstream stream;
  stream << "embed_length=\t" << knobs->embed_length << std::endl;
  stream << "use_ecc=\t" << knobs->use_ecc << std::endl;
  stream << "ecc_blocklen=\t" << knobs->ecc_blocklen << std::endl;
  stream << "freq_pool=\t" <<  knobs->freq_pool << std::endl;
  stream << "quality_out=\t" <<  knobs->quality_out << std::endl;
  stream << "random_seed=\t" <<  knobs->random_seed << std::endl;

  return stream.str();

  
}
