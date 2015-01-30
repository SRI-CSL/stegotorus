#include "flow.h"
#include "zpack.c"
#include "../src/strncasestr.h"


void free_msg_chain(flow* f) {
  msg* m = f->msg_buf_chain;



  while (m != NULL && f->chain_len > 0) {
    msg* n = m->next_msg;
    free(m);
    m = n;
  }

  f->chain_len = 0;
  f->msg_len_so_far = 0;
  f->msg_buf_chain = NULL;
}



int has_chain_gaps(flow* f) {
  msg* m = f->msg_buf_chain;

  while (m != NULL) {
    if (m->next_msg == NULL)
      return 0;

    if (m->seqno + m->len < m->next_msg->seqno) {
      fprintf(stderr, "gap seqnos: %u %u %u %d\n", m->seqno, m->len, m->next_msg->seqno, f->dport);
      return 1;
    }

    if (m->seqno + m->len  > m->next_msg-> seqno) {
      fprintf(stderr, "overlap seqnos: %u %u %u\n", m->seqno, m->len, m->next_msg->seqno);
      return 2;
    }
    m = m->next_msg;
  }

  return 0;

}


int write_inflate_msg(flow* f, FILE* file, pentry_header* ph) {
  msg* m = f->msg_buf_chain;
  char* buf;
  int pos = 0;
  char* outbuf;
  int outlen;

  u_char* hdr_end;
  u_char* hdr;
  int hdrlen;
  // int i=0;


  if (f->msg_buf_chain == NULL)
    return CHAIN_EMPTY;

  if (strnstr((char*) m->buf, "Transfer-Encoding: chunked", m->len)) {
    return MSG_INVALID; 
    // we don't handle this yet....need a loop to unzip chunks individually...
  }
  else {
   hdr_end = (u_char*) strnstr((char*) m->buf, "\r\n\r\n", m->len);
   if (hdr_end == NULL) {
     fprintf(stderr, "hdr too long?? \n");
     return MSG_INVALID;
   }

   hdr_end += 4;
  }


  hdrlen = hdr_end - m->buf;
  hdr = malloc(hdrlen);
  memcpy(hdr, m->buf, hdrlen);


  buf = malloc(f->msg_len_so_far);
  outbuf = malloc(f->msg_len_so_far * 20);

  

  pos = 0;

  if (m == NULL)
    return  CHAIN_EMPTY;


  memcpy(buf, hdr_end, m->len - hdrlen);
  pos += m->len - hdrlen;
  m = m->next_msg;

  while (m != NULL) {
    memcpy(buf+pos, m->buf, m->len);
    pos += m->len;
    m = m->next_msg;
  }

  outlen = gzInflate(buf, f->msg_len_so_far - hdrlen, outbuf, f->msg_len_so_far*20);

  if (outlen < 0) {
    fprintf(stderr, "unzip failed outlen = %d %d %d\n", outlen, pos, f->msg_len_so_far-hdrlen);
    //    printf("%s\n", hdr);
    return MSG_INVALID;
  }


  ph->length = htonl(outlen+hdrlen);
  fwrite(ph, sizeof(pentry_header), 1, file);
  fwrite(hdr, hdrlen, 1, file);
  fwrite(outbuf, outlen, 1, file);
  free(buf);
  free(outbuf);
  free(hdr);
  return 1;

}

  


int write_msg_chains(flow* f, FILE* file, pentry_header* ph) {
  msg* m = f->msg_buf_chain;
  int cnt = 0;


  if (has_chain_gaps(f))
    return CHAIN_HAS_GAPS_OVERLAPS;

  if (m == NULL)
    return  CHAIN_EMPTY;

  if (strnstr((char*) m->buf, "200 OK",  m->len) && strnstr((char*)m->buf, "Content-Encoding: gzip",  m->len))
    return write_inflate_msg(f, file, ph);

  fwrite(ph, sizeof(pentry_header), 1, file);
  

  while (m != NULL)  {
    fwrite(m->buf, m->len, 1, file);
    cnt += m->len;
    m = m->next_msg;
  }
  

  if (cnt != f->msg_len_so_far)
    fprintf(stderr, "something funky in writing message\n");
  return 1;

}


int is_valid_http_request(flow* f) {


  if (f->msg_buf_chain == NULL) 
    fprintf(stderr, "is_valid_http_request: invalid chain, shouldn't be here %d\n", f->chain_len);

  if (!strncmp((char*) f->msg_buf_chain->buf, "GET", 3) || !strncmp((char*) f->msg_buf_chain->buf, "POST", 4)) {
    msg* m = f->msg_buf_chain;
    while (m->next_msg != NULL)
      m = m->next_msg;


    if (m->buf[m->len-2] == '\r' && m->buf[m->len-1] == '\n') {
      return 1;
    }
  }


  return 0;
}




int add_msg_to_flow(flow* f, u_char* buf, uint seq, int len) {
  // if (len > PKT_MTU)
  if (len > RECV_MTU)
    return MSG_INVALID;

  if (f->chain_len >= MAX_CHAIN_LEN)
    return CHAIN_TOO_LONG;

  if (seq > seq + len)
    return MSG_SEQ_WRAP;

  msg* p = NULL;
  msg* m = f->msg_buf_chain;

  if (m == NULL) {
    m = malloc(sizeof(msg));
    bzero(m, sizeof(msg));
    m->buf = (u_char *)calloc(len, sizeof(char));
    if (!(m->buf)) {
        fprintf(stderr, "add_msg_to_flow: calloc failed; abort\n");
        exit(1);
    }
    memcpy(m->buf, buf, len);
    m->seqno = seq;
    f->chain_len = 1;
    f->msg_len_so_far += len;
    f->msg_buf_chain = m;
    m->len = len;
    return MSG_INSERTED;
  }
    


  while (m != NULL) {
    if (m->seqno == seq)
      return MSG_DUPLICATE;

    if (m->seqno < seq) {
      if (m->seqno > seq + len)
	return MSG_OVERLAP;
      p = m;
      m = m->next_msg;
      continue;
    }

    else {
      msg* n;

      if (m->seqno < seq + len)
	return MSG_OVERLAP;


      if (p == NULL) {
	p = malloc(sizeof(msg));
	bzero(p, sizeof(msg));
        p->buf = (u_char *)calloc(len, sizeof(char));
        if (!(p->buf)) {
            fprintf(stderr, "add_msg_to_flow: calloc failed; abort\n");
            exit(1);
        }
	memcpy(p->buf, buf, len);
	p->seqno = seq;
	p->next_msg = m;
	f->chain_len++;
	f->msg_len_so_far += len;
	f->msg_buf_chain = p;
	p->len = len;
	return MSG_INSERTED;	
      }
      
      n = malloc(sizeof(msg));
      bzero(n, sizeof(msg));
      n->buf = (u_char *)calloc(len, sizeof(char));
      if (!(n->buf)) {
          fprintf(stderr, "add_msg_to_flow: calloc failed; abort\n");
          exit(1);
      }
      memcpy(n->buf, buf, len);
      n->seqno = seq;
      n->next_msg = m;
      p->next_msg = n;
      f->chain_len++;
      f->msg_len_so_far += len;
      n->len = len;
      return MSG_INSERTED;	
    }    
  }

  m = malloc(sizeof(msg));
  bzero(m, sizeof(msg));
  m->buf = (u_char *)calloc(len, sizeof(char));
  if (!(m->buf)) {
      fprintf(stderr, "add_msg_to_flow: calloc failed; abort\n");
      exit(1);
  }
  memcpy(m->buf, buf, len);
  m->seqno = seq;
  p->next_msg = m;
  f->chain_len++;
  f->msg_len_so_far += len;
  m->len = len;
  return MSG_INSERTED;


 
}
