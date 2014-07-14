/* Copyright 2011, 2012, 2013, 2014 SRI International
 * See LICENSE for other credits and copying information
 */

#include <vector>
#include <sstream>

#include "protocol.h"
#include "chop_blk.h"
#include "chop_conn.h"
#include "chop_circuit.h"



chop_circuit_t::chop_circuit_t() :
  tx_queue(), recv_queue(), downstreams(), send_crypt(NULL), send_hdr_crypt(NULL), recv_crypt(NULL), recv_hdr_crypt(NULL), config(NULL),
  circuit_id(0), last_acked(0), dead_cycles(0), received_fin(0), sent_fin(0), upstream_eof(0), initialized(0) {}




chop_circuit_t::~chop_circuit_t()
{
  delete send_crypt;
  delete send_hdr_crypt;
  delete recv_crypt;
  delete recv_hdr_crypt;
  
  send_crypt = NULL;
  send_hdr_crypt = NULL;
  recv_crypt = NULL;
  recv_hdr_crypt = NULL;
}



void
chop_circuit_t::close()
{
  if (!sent_fin || !received_fin || !upstream_eof) {
    log_warn(this, "destroying active circuit: fin%c%c eof%c ds=%lu",
             sent_fin ? '+' : '-', received_fin ? '+' : '-',
             upstream_eof ? '+' : '-',
             (unsigned long)downstreams.size());
  }

  for (unordered_set<chop_conn_t *>::iterator i = downstreams.begin();
       i != downstreams.end(); i++) {
    chop_conn_t *conn = *i;

    vector<chop_circuit_t*>::iterator iter = conn->upstream_circuits.begin();
    vector<chop_circuit_t*>::iterator end = conn->upstream_circuits.end();
  
    while(1) {    
      if (*iter == this) {
        conn->upstream_circuits.erase(iter);
        break;
      }
      // circuit not found in upstream list
      log_assert(iter != end);
      iter++;
    }

    conn_do_flush(conn);
  }

  downstreams.clear();

  // The IDs for old circuits are preserved for a while (at present,
  // indefinitely; FIXME: purge them on a timer) against the
  // possibility that we'll get a junk connection for one of them
  // right after we close it (same deal as the TIME_WAIT state in
  // TCP).  Note that we can hit this case for the *client* if the
  // cover protocol includes a mandatory reply to every client message
  // and the hidden channel closed s->c before c->s: the circuit will
  // get destroyed on the client side after the c->s FIN, and the
  // mandatory reply will be to a stale circuit.
  chop_circuit_table::iterator out;
  out = config->circuits.find(circuit_id);
  log_assert(out != config->circuits.end());
  log_assert(out->second == this);
  out->second = NULL;
  circuit_t::close();
}

config_t *
chop_circuit_t::cfg() const
{
  return config;
}

void
chop_circuit_t::add_downstream(chop_conn_t *conn)
{
  log_assert(conn);

  for (unsigned int i=0; i < conn->upstream_circuits.size(); i++)
    log_assert(conn->upstream_circuits[i] != this);

  conn->upstream_circuits.push_back(this);
  downstreams.insert(conn);

  log_debug(this, "added connection <%d.%d> to %s, now %lu",
            serial, conn->serial, conn->peername,
            (unsigned long)downstreams.size());

  circuit_disarm_axe_timer(this);
}

void
chop_circuit_t::add_downstream(conn_t *cn)
{
  add_downstream(dynamic_cast<chop_conn_t *>(cn));
}

void
chop_circuit_t::drop_downstream(chop_conn_t *conn)
{
  log_assert(conn);


  vector<chop_circuit_t*>::iterator iter = conn->upstream_circuits.begin();
  vector<chop_circuit_t*>::iterator end = conn->upstream_circuits.end();

  
  while(1) {    
    if (*iter == this) {
      conn->upstream_circuits.erase(iter);
      break;
    }
    
    // circuit not found in upstream list
    log_assert(iter != end);
    iter++;
  }
	
  downstreams.erase(conn);

  log_debug(this, "dropped connection <%d.%d> to %s, now %lu",
            serial, conn->serial, conn->peername,
            (unsigned long)downstreams.size());
  // If that was the last connection on this circuit AND we've both
  // received and sent a FIN, close the circuit.  Otherwise, if we're
  // the server, arm a timer that will kill off this circuit in a
  // little while if no new connections happen (we might've lost all
  // our connections to protocol errors, or because the steg modules
  // wanted them closed); if we're the client, send chaff in a bit,
  // to enable further transmissions from the server.
  if (downstreams.empty()) {
    if (sent_fin && received_fin) {
      circuit_do_flush(this);
    } else if (config->mode == LSN_SIMPLE_SERVER) {
      circuit_arm_axe_timer(this, axe_interval());
    } else {
      uint32_t val = flush_interval();
      circuit_arm_flush_timer(this, val);
    }
  }
}

void
chop_circuit_t::drop_downstream(conn_t *cn)
{
  drop_downstream(dynamic_cast<chop_conn_t *>(cn));
}




int
chop_circuit_t::send()
{
  circuit_disarm_flush_timer(this);

  struct evbuffer *xmit_pending = bufferevent_get_input(up_buffer);
  size_t avail = evbuffer_get_length(xmit_pending);
  size_t avail0 = avail;
  bool no_target_connection = false;

  if (sent_fin)
    return 0;

  if (downstreams.empty()) {
    log_debug(this, "no downstream connections");
    no_target_connection = true;
    goto no_forward_progress;
  } 

  // Consider retransmission.
  if ((avail == 0 || tx_queue.busy()) && !(upstream_eof && !sent_fin) && config->retransmit) {
    evbuffer *block = evbuffer_new();
    int rval = find_best_to_retransmit(NULL, block);

    if (rval == 0) {
      check_for_eof();
      return 0;
    }
    
    if (rval > 0)
      return -1;
  }  

  // Send at least one block, even if there is no real data to send.
  do {
    size_t blocksize;
    chop_conn_t *target = pick_connection(avail, 0, &blocksize);

    log_debug(this, "%lu bytes to send", (unsigned long)avail);

    if (!target) {
      // this is not an error; it can happen e.g. when the server has
      // something to send immediately and the client hasn't spoken yet
      log_debug(this, "no target connection available");
      no_target_connection = true;
      break;
    }
      
    if (send_targeted(target, blocksize))
      return -1;
    
    avail = evbuffer_get_length(xmit_pending);
  } while (avail > 0);

  if (avail0 != avail) {
    check_for_eof();
    return 0;
  }


 no_forward_progress:
  dead_cycles++;
  log_debug(this, "%u dead cycles", dead_cycles);

  if (no_target_connection == false) {
    circuit_arm_axe_timer(this, axe_interval());
    check_for_eof();
    return 0;
  }

  // If we're the client and we had no target connection, try
  // reopening new connections.  If we're the server, we have to
  // just twiddle our thumbs and hope the client does that.
  if (config->mode != LSN_SIMPLE_SERVER && downstreams.size() < 64) {
    if(!config->persist_mode || downstreams.empty()){
      circuit_reopen_downstreams(this);
    }
  }

  check_for_eof();
  return 0;
}








int
chop_circuit_t::send_eof()
{
  upstream_eof = true;
  return send();
}

int
chop_circuit_t::send_special(opcode_t f, struct evbuffer *payload)
{

  size_t blocksize = 0, p = 0, d = 0;
  chop_conn_t *conn = NULL;
  uint32_t seqno;
  char fallbackbuf[4];
  struct evbuffer *block;

  if (!payload)
    payload = evbuffer_new();

  if (!payload) {
    log_warn(this, "memory allocation failure");
    return -1;
  }

  d = evbuffer_get_length(payload);
  log_assert(d <= SECTION_LEN);

  if (tx_queue.full()) {
    log_warn(this, "transmit queue full 1 , cannot send");
    return -1;
  }

  conn = pick_connection(d, d, &blocksize);

  if (!conn || blocksize < MIN_BLOCK_SIZE + d) {
    log_debug("no usable connection for special block (opcode %s, need %lu bytes, have %lu)",
              opname(f, fallbackbuf), (unsigned long)(d + MIN_BLOCK_SIZE), (unsigned long)blocksize);
    conn = 0;
    p = 0;
  } 
  else {
    p = blocksize - (d + MIN_BLOCK_SIZE);
  }

  // Regardless of whether we were able to find a connection right now,
  // enqueue the block for transmission when possible.
  // The transmit queue takes ownership of 'payload' at this point.
  seqno = tx_queue.enqueue(f, payload, p);

  // Not having a connection to use right now does not constitute a failure.
  if (!conn) {
    log_debug(conn, "NO CONNECTION so returning 0");
    return 0;
  }

  block = evbuffer_new();

  if (!block) {
    log_warn(conn, "memory allocation failure");
    return -1;
  }

  if (tx_queue.transmit(seqno, block, *send_hdr_crypt, *send_crypt)) {
    log_warn(conn, "encryption failure for block %u", seqno);
    evbuffer_free(block);
    return -1;
  }

  if (conn->send_block(block, this)) {
    evbuffer_free(block);
    return -1;
  }

  evbuffer_free(block);

  log_debug(conn, "transmitted special block %u <d=%lu p=%lu f=%s>",
            seqno, (unsigned long)d, (unsigned long)p, opname(f, fallbackbuf));

  if (config->trace_packets)
    log_warn(conn, "T:%.4f: ckt %u <ntp %u outq %lu>: send special %lu <d=%lu p=%lu f=%s>",
            TRACEPACKETS_TIMESTAMP, this->serial, this->recv_queue.window(),
            (unsigned long)evbuffer_get_length(bufferevent_get_input(this->up_buffer)),
            (unsigned long)seqno, (unsigned long)d,
            (unsigned long)p, opname(f, fallbackbuf));

  if (f == op_FIN) {
    sent_fin = true;
    read_eof = true;
  }

  if ((f == op_DAT && d > 0) || f == op_FIN)
    // We are making forward progress if we are _either_ sending or receiving data.
    dead_cycles = 0;


  return 0;
}





int 
chop_circuit_t::find_best_to_retransmit(chop_conn_t *conn, evbuffer* block) {
  int tval_best_so_far = -1;
  uint16_t padding = 0;
  uint32_t best_so_far = -1;

  for (transmit_queue::iterator i = tx_queue.begin(); i != tx_queue.end(); ++i) {
    transmit_elt& el = *i;
    size_t lo = MIN_BLOCK_SIZE + el.hdr.dlen();
    size_t hi = MAX_BLOCK_SIZE;
    size_t room  = 0;
    
    if (! (el.data))
      continue;

    if (conn == NULL) {
      conn = pick_connection(lo, lo, &room);
      if (!conn)
	continue;
    }
    else {
      if (!conn->sent_handshake) {
	lo += ENC_HANDSHAKE_LEN;
	hi += ENC_HANDSHAKE_LEN;
      }
      room = conn->steg->transmit_room(lo, lo, hi);
    }

    if (lo > room || room > hi)
      continue;

    if (tval_best_so_far == -1 || tval_best_so_far > el.last_sent) {
      best_so_far = el.hdr.seqno();
      tval_best_so_far = el.last_sent;		
      padding = room - lo;
    }
  }

  if (tval_best_so_far == -1)  {
    evbuffer_free(block);
    return -1;
  }

  transmit_queue::iterator i = tx_queue.begin(); 
  transmit_elt& el = i.peek(best_so_far);

  if (!tx_queue.retransmit(el, padding, block, *send_hdr_crypt, *send_crypt)) {
    char fallbackbuf[4];
    
    if (conn->send_block(block, this)) {
      evbuffer_free(block);
      return 1;
    }

    evbuffer_free(block);
    log_debug(conn, "retransmitted block %u <d=%lu p=%lu f=%s>",
	      el.hdr.seqno(), (unsigned long)el.hdr.dlen(),
	      (unsigned long)el.hdr.plen(),
	      opname(el.hdr.opcode(), fallbackbuf));
    
    if (config->trace_packets)
      log_warn(conn, "T:%.4f: ckt %u <ntp %u outq %lu>: resend2 %lu <d=%lu p=%lu f=%s>",
	      TRACEPACKETS_TIMESTAMP, this->serial, this->recv_queue.window(),
	      (unsigned long)evbuffer_get_length(bufferevent_get_input(this->up_buffer)),
	      (unsigned long)el.hdr.seqno(), (unsigned long)el.hdr.dlen(),
	      (unsigned long)el.hdr.plen(), opname(el.hdr.opcode(), fallbackbuf));
    return 0;
  }

  evbuffer_free(block);
  return -1;  
}





int
chop_circuit_t::send_targeted(chop_conn_t *conn)
{
  size_t avail = evbuffer_get_length(bufferevent_get_input(up_buffer));
  
  if (!(upstream_eof && !sent_fin) && config->retransmit) {

    // Consider retransmission if we have nothing new to send.
    evbuffer *block = evbuffer_new();

    if (!block) log_abort("memory allocation failed");

    int rval = find_best_to_retransmit(conn, block);
    
    // network error
    if (rval > 0)
      return -1;

    // retransmit successful
    if (rval == 0)
      return 0;
    
    // rval < 0... nothing to retransmit, so fall through and send something

  }


  if (avail > SECTION_LEN)
    avail = SECTION_LEN;
  avail += MIN_BLOCK_SIZE;

  // If we have any data to transmit, ensure we do not send a block
  // that contains no data at all.
  size_t lo = MIN_BLOCK_SIZE + (avail == MIN_BLOCK_SIZE ? 0 : 1);

  // If this connection has not yet sent a handshake, it will need to.
  size_t hi = MAX_BLOCK_SIZE;
  if (!conn->sent_handshake) {
    lo += ENC_HANDSHAKE_LEN;
    hi += ENC_HANDSHAKE_LEN;
    avail += ENC_HANDSHAKE_LEN;
  }

  size_t room = conn->steg->transmit_room(avail, lo, hi);

  

  if (room == 0) {
    //we are probably in receive mode and not ready to send yet on this connection
    // however, we shouldn't be sending an error here
    return 0;
  }


  if (room < lo || room >= hi)
    log_abort(conn, "steg size request (%lu) out of range [%lu, %lu]",
              (unsigned long)room, (unsigned long)lo, (unsigned long)hi);

  log_debug(conn, "requests %lu bytes (%s)", (unsigned long)room,
            conn->steg->cfg()->name());

  return send_targeted(conn, room);
}




int
chop_circuit_t::send_targeted(chop_conn_t *conn, size_t blocksize)
{
  size_t lo = MIN_BLOCK_SIZE, hi = MAX_BLOCK_SIZE;
  struct evbuffer *xmit_pending = bufferevent_get_input(up_buffer);
  size_t avail = evbuffer_get_length(xmit_pending);
  opcode_t op = op_DAT;

  if (!conn->sent_handshake) {
    lo += ENC_HANDSHAKE_LEN;
    hi += ENC_HANDSHAKE_LEN;
  }

  log_assert(blocksize >= lo && blocksize <= hi);

  if (avail > blocksize - lo)
    avail = blocksize - lo;
  else if (avail > SECTION_LEN)
    avail = SECTION_LEN;
  else if (upstream_eof && !sent_fin)
    // this block will carry the last byte of real data to be sent in
    // this direction; mark it as such
    op = op_FIN;

  return send_targeted(conn, avail, (blocksize - lo) - avail, op, xmit_pending);
}

int
chop_circuit_t::send_targeted(chop_conn_t *conn, size_t d, size_t p, opcode_t f,
                              struct evbuffer *payload)
{
  log_assert(payload || d == 0);
  log_assert(d <= SECTION_LEN);
  log_assert(p <= SECTION_LEN);

  if (tx_queue.full()) {
    log_warn(conn, "transmit queue full, cannot send data now");
    return -1;
  }

  struct evbuffer *data = evbuffer_new();
  if (!data) {
    log_warn(conn, "memory allocation failure");
    return -1;
  }

  if (evbuffer_remove_buffer(payload, data, d) != (int)d) {
    log_warn(conn, "failed to extract payload");
    evbuffer_free(data);
    return -1;
  }


  //careful on windows things like ostream and sstream can pull in a 64 bit time_t
  //while mingw-w64-gcc's time.h seems to pull in a 32 bit time_t
  //see Makefile.am for the crucial flag.
  //fprintf(stderr, "chop_cir: sizeof(time_t) = %d\n", sizeof(time_t));

  // The transmit queue takes ownership of 'data' at this point.
  uint32_t seqno = tx_queue.enqueue(f, data, p);


  struct evbuffer *block = evbuffer_new();
  if (!block) {
    log_warn(conn, "memory allocation failure");
    return -1;
  }
  if (tx_queue.transmit(seqno, block, *send_hdr_crypt, *send_crypt)) {
    log_warn(conn, "encryption failure for block %u", seqno);
    evbuffer_free(block);
    return -1;
  }

  if (conn->send_block(block, this)) {
    evbuffer_free(block);
    return -1;
  }
  evbuffer_free(block);

  char fallbackbuf[4];
  log_debug(conn, "transmitted block %u <d=%lu p=%lu f=%s>",
            seqno, (unsigned long)d, (unsigned long)p, opname(f, fallbackbuf));

  if (config->trace_packets)
    log_warn(conn,
            "T:%.4f: ckt %u <ntp %u outq %lu>: send %lu <d=%lu p=%lu f=%s>",
            TRACEPACKETS_TIMESTAMP, this->serial,
            this->recv_queue.window(),
            (unsigned long)evbuffer_get_length(bufferevent_get_input(this->up_buffer)),
            (unsigned long)seqno, (unsigned long)d, (unsigned long)p,
            opname(f, fallbackbuf));

  if (f == op_FIN) {
    sent_fin = true;
    read_eof = true;
  }
  if ((f == op_DAT && d > 0) || f == op_FIN)
    // We are making forward progress if we are _either_ sending or receiving data.
    dead_cycles = 0;
  return 0;
}






// N.B. 'desired' is the desired size of the _data section_, and
// 'blocksize' on output is the size to make the _entire block_.
chop_conn_t *
chop_circuit_t::pick_connection(size_t desired, size_t minimum,
                                size_t *blocksize)
{
  size_t maxbelow = 0;
  size_t minabove = MAX_BLOCK_SIZE + 1;
  chop_conn_t *targbelow = 0;
  chop_conn_t *targabove = 0;

  if(!(minimum <= SECTION_LEN)){
    log_warn("pick_connection: minimum = %lu SECTION_LEN = %lu", (unsigned long)minimum, (unsigned long)SECTION_LEN);
  }
  log_assert(minimum <= SECTION_LEN);

  if (desired > SECTION_LEN)
    desired = SECTION_LEN;

  // If we have any data to transmit, ensure we do not send a block
  // that contains no data at all.
  if (desired > 0 && minimum == 0)
    minimum = 1;

  desired += MIN_BLOCK_SIZE;
  minimum += MIN_BLOCK_SIZE;

  log_debug(this, "target block size %lu bytes", (unsigned long)desired);

  // Find the best fit for the desired transmission from all the
  // outbound connections' transmit rooms.
  for (unordered_set<chop_conn_t *>::iterator i = downstreams.begin();
       i != downstreams.end(); i++) {
    chop_conn_t *conn = *i;

    if (config->mode == LSN_SIMPLE_SERVER && conn->last_circuit_id != circuit_id)
      continue;


    // We cannot transmit on a connection whose steganography module has
    // not yet been instantiated.  (This only ever happens server-side.)
    if (!conn->steg) {
      log_debug(conn, "offers 0 bytes (no steg)");
      continue;
    }

    // We must not transmit on a connection that has not completed its
    // TCP handshake.  (This only ever happens client-side.  If we try
    // it anyway, the transmission gets silently dropped on the floor.)
    if (!conn->connected) {
      log_debug(conn, "offers 0 bytes (not connected)");
      continue;
    }

    size_t shake = conn->sent_handshake ? 0 : ENC_HANDSHAKE_LEN;
    size_t room = conn->steg->transmit_room(desired + shake,
                                            minimum + shake,
                                            MAX_BLOCK_SIZE + shake);
    if (room == 0) {
      log_debug(conn, "offers 0 bytes (%s)",
                conn->steg->cfg()->name());

      continue;
    }

    if (room < minimum + shake || room >= MAX_BLOCK_SIZE + shake)
      log_abort(conn, "steg size request (%lu) out of range [%lu, %lu]",
                (unsigned long)room,
                (unsigned long)(minimum + shake),
                (unsigned long)(MAX_BLOCK_SIZE + shake));

    log_debug(conn, "offers %lu bytes (%s)", (unsigned long)room,
              conn->steg->cfg()->name());

    if (room >= desired + shake) {
      if (room < minabove) {
        minabove = room;
        targabove = conn;
      }
    } else {
      if (room > maxbelow) {
        maxbelow = room;
        targbelow = conn;
      }
    }
  }

  log_debug(this, "minabove %lu for <%u.%u> maxbelow %lu for <%u.%u>",
            (unsigned long)minabove, serial, targabove ? targabove->serial :0,
            (unsigned long)maxbelow, serial, targbelow ? targbelow->serial :0);

  // If we have a connection that can take all the data, use it.
  // Otherwise, use the connection that can take as much of the data
  // as possible.  As a special case, if no connection can take data,
  // targbelow, targabove, maxbelow, and minabove will all still have
  // their initial values, so we'll return NULL and set blocksize to 0,
  // which callers know how to handle.
  if (targabove) {
    *blocksize = minabove;
    return targabove;
  } else {
    *blocksize = maxbelow;
    return targbelow;
  }
}

int
chop_circuit_t::maybe_send_ack()
{
  // Send acks aggressively if we are experiencing dead cycles *and*
  // there are blocks on the receive queue.  Otherwise, send them only
  // every 64 blocks received.  This heuristic will probably need
  // adjustment.

  //  if (recv_queue.window() - last_acked < 64 &&
  //    (!dead_cycles || recv_queue.empty()))
  //  return 0;

  // if ntp is 0, do not send acks
  if (recv_queue.window() == 0) {
    log_debug(this, "NO ACKS BEFORE RECEIVING FIRST BLOCK");
    return 0;
  }

  if ((recv_queue.window() - last_acked < 15) && (rand() % 3 != 0))
      return 0;

  last_acked = recv_queue.window();


  evbuffer *ackp = recv_queue.gen_ack();

  if (log_do_debug()) {
    std::ostringstream ackdump;
    debug_ack_contents(ackp, ackdump);
    log_debug(this, "sending ACK: %s", ackdump.str().c_str());
  }
  return send_special(op_ACK, ackp);
}




// Some blocks are to be processed immediately upon receipt.
int
chop_circuit_t::recv_block(uint32_t seqno, opcode_t op, evbuffer *data)
{


  switch (op) {
  case op_DAT:
  case op_FIN:
    // No special handling required.
    goto insert;

  case op_RST:
    // Remote signaled a protocol error.  Disconnect.
    log_info(this, "received RST; disconnecting circuit");
    circuit_recv_eof(this);
    evbuffer_free(data);
    goto zap;

  case op_ACK:
    if (config->trace_packets) {
      std::ostringstream ackdump;
      debug_ack_contents(data, ackdump);
      log_warn(this,
               "T:%.4f: ckt %u <ntp %u outq %lu>: recv-ack %s",
	       TRACEPACKETS_TIMESTAMP, serial,
	       recv_queue.window(),
	       (unsigned long)evbuffer_get_length(bufferevent_get_input(up_buffer)),
	       ackdump.str().c_str());       
    }

    if (tx_queue.process_ack(data))
      log_warn(this, "protocol error: invalid ACK payload");
    goto zap;

  case op_XXX:
  default:
    char fallbackbuf[4];
    log_warn(this, "protocol error: unsupported block opcode %s",
             opname(op, fallbackbuf));
    evbuffer_free(data);
    goto zap;
  }

 zap:
  // Block has been consumed; fill in the hole in the receive queue.
  op = op_DAT;
  data = evbuffer_new();

 insert:
  if (initialized == false && seqno > 10) {
    log_warn("uninitialized stale circuit... ignoring block %d\n", seqno);
    return -1;
  }

  if (seqno == 0 && initialized == false)
    initialized = true;

  recv_queue.insert(seqno, op, data);
  return 0;
}



int
chop_circuit_t::process_queue()
{
  reassembly_elt blk;
  unsigned int count = 0;
  bool pending_fin = false;
  bool pending_error = false;
  bool sent_error = false;

  while ((blk = recv_queue.remove_next()).data) {
    switch (blk.op) {
    case op_FIN:
      if (received_fin) {
        log_info(this, "protocol error: duplicate FIN");
        pending_error = true;
        break;
      }
      log_debug(this, "received FIN");
      pending_fin = true;
      // fall through - block may have data
    case op_DAT:
      if (evbuffer_get_length(blk.data)) {
        if (received_fin) {
          log_info(this, "protocol error: data after FIN");
          pending_error = true;
        } else {
          // We are making forward progress if we are _either_ sending or
          // receiving data.
          dead_cycles = 0;
          if (evbuffer_add_buffer(bufferevent_get_output(up_buffer),
                                  blk.data)) {
            log_warn(this, "buffer transfer failure");
            pending_error = true;
          }
        }
      }
      break;

    // no other opcodes should get this far
    default:
      char fallbackbuf[4];
      log_abort("f=%s block should never appear on receive queue",
                opname(blk.op, fallbackbuf));
    }

    evbuffer_free(blk.data);

    if (pending_fin && !received_fin) {
      circuit_recv_eof(this);
      received_fin = true;
    }
    if (pending_error && !sent_error) {
      // there's no point sending an RST in response to an RST or a
      // duplicate FIN
      if (blk.op != op_RST && blk.op != op_FIN)
        send_special(op_RST, 0);
      sent_error = true;
    }
    count++;
  }

  log_debug(this, "processed %u blocks", count);
  if (sent_error)
    return -1;

  if (maybe_send_ack())
    return -1;

  // It may have become possible to send queued data or a FIN.
  /*  if (evbuffer_get_length(bufferevent_get_input(up_buffer))
      || (upstream_eof && !sent_fin))
    return send();
  */

  check_for_eof();
  return 0;
}




void 
chop_circuit_t::check_for_eof()
{
  // If we're at EOF both ways, close all connections, sending first
  // if necessary.
  if (sent_fin && received_fin) {
    log_debug(this, "sent and received FIN");
    circuit_disarm_flush_timer(this);
    for (unordered_set<chop_conn_t *>::iterator i = downstreams.begin();
         i != downstreams.end(); i++) {
      chop_conn_t *conn = *i;
      if (conn->must_send_p())
        conn->send(0);
      conn_send_eof(conn);
    }
  }

  // If we're the client we have to keep trying to talk as long as we
  // haven't both sent and received a FIN, or we might deadlock.
  else if (config->mode != LSN_SIMPLE_SERVER) {
    log_debug(this, "client arming flush timer%s%s",
              sent_fin ? " (sent FIN)" : "",
              received_fin ? " (received FIN)": "");
    circuit_arm_flush_timer(this, flush_interval());
  }

}
