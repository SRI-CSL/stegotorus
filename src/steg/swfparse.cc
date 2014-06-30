/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#include <event2/buffer.h>
#include "util.h"
#include "swfSteg.h"
#include "compression.h"
#include "connections.h"
#include "payloads.h"
#include "base64.h"
#include "headers.h"
#include "protocol.h"
#include "strncasestr.h"
#include "oshacks.h"






rcode_t
shift_copy(unsigned char*& buf1, size_t& sz1, unsigned char* & buf2, size_t& sz2, size_t len) {


  if (sz1 < len || sz2 < len)
    goto err;

  if (memncpy(buf1, sz1, buf2, len) != RCODE_OK)
    goto err;


  buf1 += len;
  buf2 += len;
  sz1 -= len;
  sz2 -= len;  
  return RCODE_OK;

 err:
  log_warn("shift copy failed %" PriSize_t " %" PriSize_t " %" PriSize_t, sz1, sz2, len);
  return RCODE_ERROR;
} 




void 
update_id (unsigned char* in_swf, unsigned int &id_so_far) {
  unsigned int id = ((short*) in_swf)[0];

  if (id > id_so_far) {
    id_so_far = id;
  }
}






rcode_t
add_definesprite_tag(unsigned char*& out_swf, size_t& out_sz, unsigned char*& b64_buf, 
		     size_t& b64_len, unsigned int& id_so_far) {

  size_t bufptr_sz = 1000 + b64_len;
  unsigned char* buf = (unsigned char *) xmalloc(bufptr_sz);
  unsigned char* bufptr = buf;

  
  ((short*) buf)[0] = ++id_so_far;
  buf[2] = 1;
  buf[3] = 0;
  buf += 4;

  if (b64_buf[b64_len] == '.')
    b64_len--;


  while(b64_len > 0) {
    unsigned short cnt = rand() % 20 + 1;
    ((short*) buf)[0] = (0x1a << 6) | 0x3F;

    if ( cnt >= b64_len)
      cnt = b64_len;

    buf += 2;
    cnt = cnt + 7;  // 1 (0x26)), 2 (depth), 2 (id), 1, string, 1 (null char)
    ((unsigned int*) buf)[0] = cnt; 
    buf += 4;
    buf[0] = 0x26;
    buf++;
    buf[0] = rand() % 3;  // 0 for depth
    buf++;
    buf[0] = 0;
    buf++;
    ((short*) buf)[0] = ++id_so_far;
    buf += 2;
    buf[0] = 0;
    buf++;

    if (memncpy(buf, bufptr_sz - (buf - bufptr), b64_buf, cnt-7) != RCODE_OK)
      goto err;

    b64_buf = b64_buf + cnt - 7;
    b64_len = b64_len - cnt + 7;
    
    buf = buf + cnt - 7;
    buf[0] = 0;
    buf++;
  }

  // showframe
  ((short*) buf)[0] = (0x1 << 6);

  // endframe
  ((short*) buf)[1] = 0;
  buf += 4;

  if (out_sz > (unsigned int) (buf - bufptr + 6)) {
    ((short*) out_swf)[0] = (0x27 << 6) | 0x3F;
    out_swf = out_swf + 2;
    ((unsigned int*) out_swf)[0] = buf - bufptr;
    out_swf = out_swf + 4;
    out_sz = out_sz - 6;

    if (memncpy(out_swf, out_sz, bufptr, buf - bufptr) != RCODE_OK)
      goto err;
    
    out_swf = out_swf + (buf - bufptr);
    out_sz = out_sz - (buf - bufptr);
  }
  else {
    log_warn("swfreader: outbuf too small\n");
    goto err;
  }
  
  free(bufptr);
  return RCODE_OK;

 err:
  free(bufptr);
  log_warn("add_define_sprite_tag failed\n");
  return RCODE_ERROR;
  
}




rcode_t
handle_tag(unsigned int tag, size_t& taglen, unsigned char* in_swf, unsigned char* out_swf, 
	   size_t out_sz, unsigned char*& b64_buf, size_t& b64_len, size_t& bytes_copied) {

  bytes_copied = 0;
  unsigned int err_code = 0;
 
  // DEFINESPRITE
  if (tag == 39) {

    // skip  4 bytes of sprite_id and frame_count
    if (shift_copy(out_swf, out_sz, in_swf, taglen, 4) != RCODE_OK) {
      err_code = 1;
      goto err;
    }

    bytes_copied += 4;

    do {
      unsigned int t2 = (((short*) in_swf)[0] & 0xffc0) >> 6;
      size_t t2len = (((short*) in_swf)[0] & 0x003f);
      int flag = 0;
      
      if (shift_copy(out_swf, out_sz, in_swf, taglen, 2) != RCODE_OK) {
	err_code = 2;
	goto err;
      }

      bytes_copied += 2;

      if (t2len == 0x3f) {
	// note this is only 4 bytes
	t2len = * ((uint32_t*) in_swf);

      	if (shift_copy(out_swf, out_sz, in_swf, taglen, 4) != RCODE_OK) {
	  err_code = 3;
	  goto err;
	}
	bytes_copied += 4;
      }

      if (t2 == 0x1a && in_swf[0] == 0x26) {
	in_swf[5] = 0;
	flag = 1;
      }

      if (shift_copy(out_swf, out_sz, in_swf, taglen, t2len) != RCODE_OK) {
	err_code = 4;
	goto err;
      }
 
      bytes_copied += t2len;

      if ((flag == 1 && b64_len > 0)) {
	if ((t2len - 6 <= b64_len)) {
	  out_swf = out_swf - t2len + 6;

	  if (bytes_copied < t2len - 6) {
	    err_code = 5;
	    goto err;
	  }

	  if (memncpy(out_swf, out_sz + t2len - 6, b64_buf, t2len - 7) != RCODE_OK) {
	    err_code = 6;
	    goto err;
	  }

	  b64_buf += t2len - 7;
	  b64_len -= t2len - 7;
	  out_swf = out_swf + t2len - 6;
	}
	else {
	  out_swf = out_swf - t2len + 6;

	  if (bytes_copied < t2len - 6) {
	    err_code = 7;
	    goto err;
	  }

	  if (memncpy(out_swf, out_sz + t2len - 6, b64_buf, b64_len) != RCODE_OK) {
	    err_code = 8;
	    goto err;
	  }
       
	  out_swf[b64_len] = '.';
	  b64_buf += b64_len;
	  b64_len = 0;
	  out_swf = out_swf + t2len - 6;
	}
      }	    
    } while (taglen > 0);
  } 
  
  return RCODE_OK;

 err:
    if (err_code != 0)
      log_warn("handle_tag failed %d\n", err_code);

    return RCODE_ERROR;
}






rcode_t
recover_from_tag(unsigned int tag, size_t taglen, unsigned char* in_swf, 
		 size_t in_sz, unsigned char*& out_data, size_t& out_sz,
		 size_t& recovered_so_far) {

  size_t out_sz_orig = out_sz;

  // DEFINESPRITE
  if (tag == 39) {

    if (in_sz < 4) 
      goto err;

    in_swf = in_swf + 4;
    in_sz = in_sz - 4;
    

    taglen = taglen - 4;

    do {
      unsigned int t2 = (((short*) in_swf)[0] & 0xffc0) >> 6;
      size_t t2len = (((short*) in_swf)[0] & 0x003f);

      if (in_sz < 2) 
	goto err;

      in_swf = in_swf + 2;
      in_sz = in_sz -2;
      taglen = taglen - 2;

      if (t2len == 0x3f) {
	// note this is only 4 bytes
	t2len = * ((uint32_t*) in_swf);
	in_swf = in_swf + 4;
	in_sz = in_sz - 4;
	taglen = taglen - 4;
      }

      if (t2 == 0x1a && in_swf[0] == 0x26 && out_sz > (t2len - 7)) {

	for (unsigned int j=0; j < t2len - 7; j++) {

	  if (in_sz < 6+j)
	    goto err;

	  out_data[0] = in_swf[6+j];

	  if (in_swf[6+j] == '.') {
	    goto done;
	  }
	 
	  out_data++;
	  out_sz --;
	}
      }

      if (in_sz < t2len)
	goto err;

      in_swf = in_swf + t2len;
      in_sz = in_sz - t2len;
      taglen = taglen - t2len;	    
    } while (taglen > 0);   
  } 

 done:
  recovered_so_far = recovered_so_far + out_sz_orig - out_sz;
  return RCODE_OK;
  
 err:
  log_warn("invalid swf in recover tag\n");
  return RCODE_ERROR;
}








bool
is_ready_to_insert(unsigned char* in_swf, size_t in_sz) {

  unsigned int tag1 = (((short*) in_swf)[0] & 0xffc0) >> 6;
  size_t tag1_len = (((short*) in_swf)[0] & 0x3f);

  unsigned int tag2, tag3, tag4;
  size_t tag2_len, tag3_len;


  if (tag1 == 0)
    return true;

  //DOABC, SHOWFRAME, SYMBOLCLASS
  if (tag1 != 82 && tag1 != 1 && tag1 != 76)
    return false;

  if (in_sz < 2)
    return false;

  in_swf += 2;
  in_sz -= 2;
  
  if (tag1_len == 0x3f) {
    tag1_len = * ((size_t*) in_swf);

    if (in_sz <= 4 + tag1_len)
      return false;

    in_swf += 4;
    in_swf += tag1_len;
  }

  // tag2
  tag2 = (((short*) in_swf)[0] & 0xffc0) >> 6;
  tag2_len = (((short*) in_swf)[0] & 0x3f);


  if (tag2 == 0)
    return true;

  //DOABC, SHOWFRAME, SYMBOLCLASS
  if (tag2 != 82 && tag2 != 1 && tag2 != 76)
    return false;

  if (in_sz < 2)
    return false;

  in_swf += 2;
  in_sz -= 2;
  
  if (tag2_len == 0x3f) {
    tag2_len = * ((size_t*) in_swf);

    if (in_sz <= 4 + tag2_len)
      return false;

    in_swf += 4;
    in_swf += tag2_len;
  }

  // tag 3
  tag3 = (((short*) in_swf)[0] & 0xffc0) >> 6;
  tag3_len = (((short*) in_swf)[0] & 0x3f);


  if (tag3 == 0)
    return true;

  //DOABC, SHOWFRAME, SYMBOLCLASS
  if (tag3 != 82 && tag3 != 1 && tag3 != 76)
    return false;

  if (in_sz < 2)
    return false;

  in_swf += 2;
  in_sz -= 2;
  
  if (tag3_len == 0x3f) {
    tag3_len = * ((size_t*) in_swf);

    if (in_sz <= 4 + tag3_len)
      return false;

    in_swf += 4;
    in_swf += tag3_len;
  }

  // tag 4
  tag4 = (((short*) in_swf)[0] & 0xffc0) >> 6;

  if (tag4 == 0)
    return true;

  return false;
}



rcode_t
parse_swf(unsigned char* in_swf, size_t in_sz, unsigned char* out_swf, size_t out_sz, 
	  unsigned char* b64_buf, size_t b64_len, size_t& bytes_consumed) {

  size_t nbits = ((in_swf[0]  & 0xf8) >> 3) * 4 + 5;
  size_t skip = nbits / 8;
  size_t out_sz_orig = out_sz;
  unsigned int id_so_far = 0;
  
  if (nbits % 8 > 0)
    skip++;
  
  if (shift_copy(out_swf, out_sz, in_swf, in_sz, skip + 4) != RCODE_OK) {
    log_warn("shift_copy failed in parse_swf, #1");
    goto err;
  }

  do {
    unsigned int tag = (((short*) in_swf)[0] & 0xffc0) >> 6;
    size_t taglen = (((short*) in_swf)[0] & 0x3f);
    size_t cnt = 0;

    if (is_ready_to_insert(in_swf, in_sz) && b64_len > 0) {
      if (add_definesprite_tag(out_swf, out_sz, b64_buf, b64_len, id_so_far) != RCODE_OK)
	goto err;
    }

    if (shift_copy(out_swf, out_sz, in_swf, in_sz, 2) != RCODE_OK) {
      log_warn("shift_copy failed in parse_swf, #2");
      goto err;
    }

    if (tag == 0)
      break;

    // long header
    if (taglen == 0x3f) {      
      taglen = * ((uint32_t*) in_swf);
      if (shift_copy(out_swf, out_sz, in_swf, in_sz, 4) != RCODE_OK) {
	log_warn("shift_copy failed in parse_swf, #3");
	goto err;
      }
    }

    /* DEFINESPRITE, DEFINESHAPE, DEFINESHAPE2, DEFINESHAPE3, DEFINESHAPE4, DEFINEEDITTEXT, 
       DEFINEFONT2, DEFINEFONT3, DEFINEBUTTON2, DEFINEBITSLOSSLESS, DEFINEBITSLOSSLESS2, 
       DEFINEBITSJPEG, DEFINEBITSAJPEG2, DEFINEBITSJPEG3, DEFINETEXT */
    if (tag == 39 || tag == 2 || tag == 22 || tag == 32 || tag == 83 || tag == 37 || 
        tag == 48 || tag == 75 || tag == 34 || tag == 20 || tag == 36 || 
        tag == 6 || tag == 21 || tag == 35 || tag == 11) 
      update_id(in_swf, id_so_far);

    if (tag == 39) {
      if (handle_tag(tag, taglen, in_swf, out_swf, out_sz, b64_buf, b64_len, cnt) != RCODE_OK)
	goto err;
    }
    else {
      cnt = taglen;

      if (taglen > out_sz) {
        log_warn("parse_swf: invalid taglen %" PriSize_t " %" PriSize_t, taglen, out_sz);
        goto err;
      }

      if (taglen > 0) {
	if (memncpy(out_swf, out_sz, in_swf, taglen) != RCODE_OK)
	  goto err;
      }
    }

    if (in_sz < taglen || out_sz < cnt)
      goto err;

    in_swf = in_swf + taglen;
    in_sz -= taglen;
    out_swf = out_swf + cnt;
    out_sz -= cnt;
  } while (1);

  bytes_consumed = out_sz_orig - out_sz;
  return RCODE_OK;

 err:
  log_warn("parse_swf failed");
  return RCODE_ERROR;
}





rcode_t
recover_data(unsigned char* in_swf, size_t in_sz, 
	     unsigned char* out_data, size_t out_sz,
	     size_t& rdatalen) 
{

  size_t nbits = ((in_swf[0]  & 0xf8) >> 3) * 4 + 5;
  size_t skip = nbits / 8;
  size_t recovered_so_far = 0;

  memset(out_data, 0, out_sz);
  
  if (nbits % 8 > 0)
    skip++;

  if (in_sz < skip + 4)
    goto err;

  in_swf = in_swf + skip + 4;
  in_sz = in_sz - skip - 4;

  do {    
    unsigned int tag = (((short*) in_swf)[0] & 0xffc0) >> 6;
    size_t taglen = (((short*) in_swf)[0] & 0x3f);

    if (is_ready_to_insert(in_swf, in_sz)) 
      goto done;

    in_swf = in_swf + 2;
    in_sz = in_sz - 2;
        
    if (tag == 0)
      break;

    // long header
    if (taglen == 0x3f) {      
      taglen = * ((uint32_t*) in_swf);
      in_swf = in_swf + 4;
      in_sz = in_sz - 2;
    }

    if (tag == 39) {
      if (recover_from_tag(tag, taglen, in_swf, in_sz, out_data, out_sz, recovered_so_far) != RCODE_OK)
	goto err;

      if (out_data[0] == '.')
	goto done;
    }

    in_swf = in_swf + taglen;
    in_sz -= taglen;
  } while (1);

 done:
  out_data[0] = 0;
  rdatalen = recovered_so_far;
  return RCODE_OK;

 err:
  return RCODE_ERROR;

}






