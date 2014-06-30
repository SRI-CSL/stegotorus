/* Copyright 2011, 2012, 2013, 2014 SRI International
 * See LICENSE for other credits and copying information
 */

#include <vector>
#include <sstream>

#include "protocol.h"
#include "types.h"
#include "steg/crypto.h"
#include "chop_blk.h"
#include "chop_conn.h"
#include "chop_circuit.h"

chop_conn_t::chop_conn_t() : config(NULL), upstream_circuits(), steg(NULL), recv_pending(NULL), must_send_timer(NULL), sent_handshake(0), no_more_transmissions(0), last_circuit_id(0)
{ }



chop_conn_t::~chop_conn_t()
{
  if (this->must_send_timer) {
    assert(event_initialized(must_send_timer));
    event_free(this->must_send_timer);
    this->must_send_timer = NULL;
  }
  if (steg)
    delete steg;
  evbuffer_free(recv_pending);
}


void
chop_conn_t::close()
{
  log_debug("chop_conn_t::close()@%p called; upstream_circuits.size() = %d", this, (int)upstream_circuits.size());
  
  if (this->must_send_timer) {
    assert(event_initialized(must_send_timer));
    event_del(this->must_send_timer);
  }
  
 
  vector<chop_circuit_t*>::iterator iter = upstream_circuits.begin();
  vector<chop_circuit_t*>::iterator end = upstream_circuits.end();
    
  while(iter != end) {   
    chop_circuit_t* circ = *iter;
    circ->downstreams.erase(this);
    log_debug("chop_conn_t@%p removed from %p", this, circ);

    if (circ->downstreams.empty()) {
      if (circ->sent_fin && circ->received_fin) {
        circuit_do_flush(circ);
      } else if (config->mode == LSN_SIMPLE_SERVER) {
        circuit_arm_axe_timer(circ, circ->axe_interval());
      } else {
        circuit_arm_flush_timer(circ, circ->flush_interval());
      }
    }
    
    iter++;
  }
  
  upstream_circuits.clear();  
  conn_t::close();
}



circuit_t *
chop_conn_t::circuit() const
{
  if (upstream_circuits.size() == 0)
    return NULL;
  
  return upstream_circuits[0];
}


int
chop_conn_t::maybe_open_upstream()
{
  // We can't open the upstream until we have a circuit ID.
  return 0;
}



int
chop_conn_t::send_block(struct evbuffer *block, chop_circuit_t* upstream)
{

  size_t enc_datalen = 0;
  uchar* enc_data = NULL;

  if (!sent_handshake) {
    if (!upstream || upstream->circuit_id == 0)
      log_abort(this, "handshake: can't happen: up%c cid=%u",
                upstream ? '+' : '-', upstream ? upstream->circuit_id : 0);
    struct handshake hs;
    
    hs.random = rand();
    hs.circuit_id = upstream->circuit_id;
    hs.random2 = rand();
    hs.cksum = hs.random + hs.random2 + upstream->circuit_id;

    if (config->shared_secret == NULL)
      enc_data = defiant_pwd_encrypt(passphrase, (const uchar*) &hs, sizeof(hs), &enc_datalen);
    else
      enc_data = defiant_pwd_encrypt(config->shared_secret, (const uchar*) &hs, sizeof(hs), &enc_datalen);


    if (enc_datalen != ENC_HANDSHAKE_LEN) {
      log_warn(this, "unexpected enc_datalen");
      goto err;
    }

    if (evbuffer_prepend(block, (void *)enc_data, ENC_HANDSHAKE_LEN)) {
      log_warn(this, "failed to prepend encrypted handshake to first block");
      goto err;
    }

    free(enc_data);
    enc_data = NULL;
  }

  if (steg->transmit(block) != TRANSMIT_GOOD) {
    log_warn(this, "failed to transmit block");
    goto err;
  }

  // HACK FOR JUMPBOX to work.. we send the handshake bytes with every block
  // sent_handshake = true;

  if (must_send_timer)
    evtimer_del(must_send_timer);
  return 0;

 err:
  if (enc_data != NULL) free(enc_data);
  return -1;
}




int
chop_conn_t::handshake()
{
  // The actual handshake is generated in chop_conn_t::send so that it
  // can be merged with a block if possible; however, we use this hook
  // to ensure that the client sends _something_ ASAP after each new
  // connection, because the server can't forward traffic, or even
  // open a socket to its own upstream, until it knows which circuit
  // to associate this new connection with.  Note that in some cases
  // it's possible for us to have _already_ sent something on this
  // connection by the time we get called back!  Don't do it twice.

  if (config->mode != LSN_SIMPLE_SERVER && !sent_handshake)
    send(1);
  return 0;
}





int
chop_conn_t::recv_handshake(chop_circuit_t*& ckt)
{
  uchar enc_data[ENC_HANDSHAKE_LEN];
  struct handshake* hs;
  uint32_t circuit_id;
  size_t hslen = 0;

  ckt = NULL;

  if (evbuffer_remove(recv_pending, (void *)&enc_data, ENC_HANDSHAKE_LEN) != (unsigned int) ENC_HANDSHAKE_LEN)
    return -1;

  if (config->shared_secret == NULL)
    hs = (struct handshake*) defiant_pwd_decrypt(passphrase, enc_data, ENC_HANDSHAKE_LEN, &hslen);
  else
    hs = (struct handshake*) defiant_pwd_decrypt(config->shared_secret, enc_data, ENC_HANDSHAKE_LEN, &hslen);

  if (hslen != sizeof(struct handshake)) {
    log_warn("unexpected size in handkshake received\n");
    free(hs);
    return -1;
  }

  
  if (hs->random + hs->random2 + hs->circuit_id != hs->cksum) {
    log_warn("handshake checksum failed\n");
    free(hs);
    return -1;
  }

  circuit_id = hs->circuit_id;
  free(hs);
  

  for (unsigned int i=0; i < upstream_circuits.size(); i++) {
    if (upstream_circuits[i]->circuit_id == circuit_id) {
      ckt = upstream_circuits[i];
      return 0;
    }
  }

      
  if(config->mode != LSN_SIMPLE_SERVER)
     return -1;
  

  chop_circuit_table::value_type in(circuit_id, (chop_circuit_t *)0);
  std::pair<chop_circuit_table::iterator, bool> out
    = this->config->circuits.insert(in);


  if (!out.second) { // element already exists
    if (!out.first->second) {
      log_debug(this, "stale circuit");
      return 0;
    }
    ckt = out.first->second;
    log_debug(this, "found circuit to %s", ckt->up_peer);
  } else {
    ckt = dynamic_cast<chop_circuit_t *>(circuit_create(this->config, 0));
    if (!ckt) {
      log_warn(this, "failed to create new circuit");
      return -1;
    }

    if (circuit_open_upstream(ckt)) {
      log_warn(this, "failed to begin upstream connection");
      ckt->close();
      return -1;
    }
    log_debug(this, "created new circuit to %s", ckt->up_peer);
    ckt->circuit_id = circuit_id;
    out.first->second = ckt;
  }

  ckt->add_downstream(this);

  return 0;
}





int
chop_conn_t::recv()
{

  chop_circuit_t* upstream = NULL;
  recv_t rval = steg->receive(recv_pending);
  char fallbackbuf[4];
  uint8_t decodebuf[MAX_BLOCK_SIZE];
  uint8_t ciphr_hdr[HEADER_LEN];
  evbuffer *data;


  if (rval == RECV_BAD) {
    log_warn(this, "steg->receive failed");
    return -1;
  }
  
  if (rval == RECV_INCOMPLETE)
    return 0;
  

  // If that succeeded but did not copy anything into recv_pending,
  // wait for more data.
  if (evbuffer_get_length(recv_pending) == 0){
    log_warn(this, "no data received");
    steg->corrupted_reception();
    return 0;
  }

  if (upstream_circuits.size() == 0) {
    if (config->mode != LSN_SIMPLE_SERVER) {
      // We're the client.  Client connections start out attached to a
      // circuit; therefore this is a server-to-client message that
      // crossed with the teardown of the circuit it belonged to, and
      // we don't have the decryption keys for it anymore.
      // By construction it must be chaff, so just throw it away.
      log_debug(this, "discarding chaff after circuit closed");
      log_assert(!must_send_p());
      conn_do_flush(this);
      return 0;
    }

    // We're the server. Try to receive a handshake.
    if (recv_handshake(upstream))  {
      unsigned int bytes = steg->corrupted_reception();
      evbuffer_drain(recv_pending, bytes);
      log_warn(this, "steg->corrupted_reception() A");
     return -1;
    }

    // If we get here and ->upstream is not set, this is a connection
    // for a stale circuit: that is, a new connection made by the
    // client (to draw more data down from the server) that crossed
    // with a server-to-client FIN, the client-to-server FIN already
    // having been received and processed.  We no longer have the keys
    // to decrypt anything after the handshake, but it's either chaff
    // or a protocol error.  Either way, we can just drop the
    // connection, possibly sending a response if the cover protocol
    // requires one.
    if (upstream_circuits.size() == 0) {
      if (must_send_p())
        send(3);
      conn_do_flush(this);
      return 0;
    }
  }
  else if (recv_handshake(upstream)) {
    size_t bytes = steg->corrupted_reception();
    evbuffer_drain(recv_pending, bytes);
    log_warn(this, "steg->corrupted_reception() B");
    return -1;
  }


  for (;;) {
    size_t avail = evbuffer_get_length(recv_pending);
    if (avail == 0)
      break;

    log_debug(this, "%lu bytes available", (unsigned long)avail);

    if (avail < MIN_BLOCK_SIZE) {
      // incomplete block frame of size 1 or 2 is common for SWF
      // due to base64 padding (see HTTP.cc)      
      if (avail > 2)  {
        unsigned int bytes = steg->corrupted_reception();
        evbuffer_drain(recv_pending, bytes);
        log_warn(this, "incomplete block framing %d \n", (int) avail);
      }
      else {
        evbuffer_drain(recv_pending, avail);
        log_debug(this, "incomplete block framing.. draining %d \n", (int) avail);
      }
      break;
    }

    if (evbuffer_copyout(recv_pending, ciphr_hdr, HEADER_LEN) !=
        (ssize_t)HEADER_LEN) {
      log_warn(this, "failed to copy out %lu bytes (header)", (unsigned long)HEADER_LEN);
      steg->corrupted_reception();
      log_warn(this, "steg->corrupted_reception() C");    
      break;
    }

    if (upstream == NULL || upstream->recv_hdr_crypt == NULL)
      return -1;

    header hdr(ciphr_hdr, *upstream->recv_hdr_crypt, upstream->recv_queue.window());

    if (!hdr.valid()) {
      uint8_t c[HEADER_LEN];
      upstream->recv_hdr_crypt->decrypt(c, ciphr_hdr);

      log_info(this, "invalid block header: %02x%02x%02x%02x|%02x%02x|%02x%02x|%s|%02x|"
               "%02x%02x%02x%02x%02x%02x", c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7],
               opname(c[8], fallbackbuf), c[9], c[10], c[11], c[12], c[13], c[14], c[15]);

      if (config->trace_packets)
        log_warn(this, "T:%.4f: ckt %u <ntp %u outq %lu>: recv-error "
                "%02x%02x%02x%02x <d=%02x%02x p=%02x%02x f=%s r=%02x "
                "c=%02x%02x%02x%02x%02x%02x>",
                TRACEPACKETS_TIMESTAMP, upstream->serial,
                upstream->recv_queue.window(),
                (unsigned long)evbuffer_get_length(bufferevent_get_input(upstream->up_buffer)),
                c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7],
                opname(c[8], fallbackbuf),
                c[9], c[10], c[11], c[12], c[13], c[14], c[15]);

      log_warn(this, "DEF: invalid block header");
      steg->corrupted_reception();
      break;
    }

    if (avail < hdr.total_len()) {
      log_warn(this, "incomplete block (avail:  %lu need %lu bytes [%lu/%lu])",
               (unsigned long)avail, (unsigned long)hdr.total_len(),
	       (unsigned long)hdr.dlen(), (unsigned long)hdr.plen());
      steg->corrupted_reception();
      log_warn(this, "steg->corrupted_reception() D");
      break;
    }


    if (evbuffer_drain(recv_pending, HEADER_LEN) ||
        evbuffer_remove(recv_pending, decodebuf, hdr.total_len() - HEADER_LEN)
        != (ssize_t)(hdr.total_len() - HEADER_LEN)) {
      log_warn(this, "failed to copy block to decode buffer");
      return -1;
    }

    if (upstream->recv_crypt->decrypt(decodebuf,
                                      decodebuf, hdr.total_len() - HEADER_LEN,
                                      ciphr_hdr, HEADER_LEN)) {
      log_warn("MAC verification failure");
      steg->corrupted_reception();
      return -1;
    }

    steg->successful_reception();

    log_debug(this, "receiving block %u <d=%lu p=%lu f=%s r=%u>",
              hdr.seqno(), (unsigned long)hdr.dlen(), (unsigned long)hdr.plen(),
              opname(hdr.opcode(), fallbackbuf),
              hdr.rcount());

    if (config->trace_packets)
      log_warn(this, "T:%.4f: ckt %u <ntp %u outq %lu>: recv %lu <d=%lu p=%lu f=%s r=%u>",
              TRACEPACKETS_TIMESTAMP, upstream->serial, upstream->recv_queue.window(),
	      (unsigned long)evbuffer_get_length(bufferevent_get_input(upstream->up_buffer)),
              (unsigned long)hdr.seqno(), (unsigned long)hdr.dlen(),
              (unsigned long)hdr.plen(), opname(hdr.opcode(), fallbackbuf),
              hdr.rcount());

    data = evbuffer_new();

    if (!data || (hdr.dlen() && evbuffer_add(data, decodebuf, hdr.dlen()))) {
      log_warn(this, "failed to extract data from decode buffer");
      evbuffer_free(data);
      return -1;
    }

    if (upstream->recv_block(hdr.seqno(), hdr.opcode(), data))
      return -1; // insert() logs an error

    if (config->mode == LSN_SIMPLE_SERVER)
      last_circuit_id = upstream->circuit_id;
  }

  return upstream->process_queue();
}

int
chop_conn_t::recv_eof()
{
  // Consume any not-yet-processed incoming data.  It's possible for
  // us to get here before we've processed _any_ data -- including the
  // handshake! -- from a new connection, so we have to do this before
  // we look at ->upstream.  */
  if (evbuffer_get_length(inbound()) > 0) {

    // If there's anything left in the buffer at this point, it's a protocol error.
    if (recv() || evbuffer_get_length(inbound()) > 0)
      return -1;
  }

  // We should only drop the connection from the circuit if we're no
  // longer sending covert data in the opposite direction _and_ the
  // cover protocol does not need us to send a reply (i.e. the
  // must_send_timer is not pending).

  for (unsigned int i=0; i < upstream_circuits.size(); i++) {
    if ((upstream_circuits[i]->sent_fin || no_more_transmissions) &&
	!must_send_p() && evbuffer_get_length(outbound()) == 0)
    upstream_circuits[i]->drop_downstream(this);
  }

  return 0;
}

void
chop_conn_t::expect_close()
{
  read_eof = true;
}

void
chop_conn_t::cease_transmission()
{
  no_more_transmissions = true;
  if (must_send_timer)
    evtimer_del(must_send_timer);
  conn_do_flush(this);
}

void
chop_conn_t::transmit_soon(unsigned long milliseconds)
{
  struct timeval tv;

  log_debug(this, "must send within %lu milliseconds", milliseconds);

  tv.tv_sec = milliseconds / 1000;
  tv.tv_usec = (milliseconds % 1000) * 1000;

  // Allocated it on a first need basis
  if (!must_send_timer) {
    must_send_timer = evtimer_new(config->base, must_send_timeout, this); 
  }

  assert(event_initialized(must_send_timer));
  evtimer_add(must_send_timer, &tv);
}




void
chop_conn_t::send(int site)
{

  size_t room;
  struct evbuffer *chaff = NULL;


  if (must_send_timer) {
    assert(event_initialized(must_send_timer));
    evtimer_del(must_send_timer); 
  }

  if (!steg) {
    log_warn(this, "send() called with no steg module available");
    conn_do_flush(this);
    return;
  }

  // When this happens, we must send _even if_ we have no upstream to
  // provide us with data.  For instance, to preserve the cover
  // protocol, we must send an HTTP reply to each HTTP query that
  // comes in for a stale circuit.
  if (upstream_circuits.size() > 0) {
    log_debug(this, "must send");
    size_t i = 0;

    if (config->mode == LSN_SIMPLE_SERVER) {
      while (i < upstream_circuits.size()) {
	if (upstream_circuits[i]->circuit_id == last_circuit_id)
	  break;
	if (i == upstream_circuits.size()) {
	  log_warn("circuit_id not found in conn upstreams.. shouldn't happen %d", last_circuit_id);
	  i = 0;
	  break;
	}
	i++;
      }
    }

    if (upstream_circuits[i]->send_targeted(this)) {
      upstream_circuits[i]->drop_downstream(this);
      conn_do_flush(this);
    }  
    return;
  }
  
  room = steg->transmit_room(MIN_BLOCK_SIZE, MIN_BLOCK_SIZE, MAX_BLOCK_SIZE);
  
  // likely implies we still haven't received the full request from the client
  if (room == 0)
    return;

  log_warn(this, "must send (no upstream)");
  
  if (room < MIN_BLOCK_SIZE || room >= MAX_BLOCK_SIZE) {
    print_trace();
    log_abort(this, "steg size request (%lu) out of range [%lu, %lu] @ site = %d upstream_circuits.size = %d",
	      (unsigned long)room, (unsigned long)MIN_BLOCK_SIZE,
	      (unsigned long)MAX_BLOCK_SIZE, site, (int)upstream_circuits.size());
  }
    
  // Since we have no upstream, we can't encrypt anything; instead,
  // generate random bytes and feed them straight to steg_transmit.
  chaff = evbuffer_new();
  struct evbuffer_iovec v;

  if (!chaff || evbuffer_reserve_space(chaff, room, &v, 1) != 1 || v.iov_len < room) {
      log_warn(this, "memory allocation failed");
      if (chaff)
        evbuffer_free(chaff);
      conn_do_flush(this);
      return;
  }

  v.iov_len = room;
  rng_bytes((uint8_t *)v.iov_base, room);

  if (evbuffer_commit_space(chaff, &v, 1)) {
    log_warn(this, "evbuffer_commit_space failed");
    if (chaff)
      evbuffer_free(chaff);
    conn_do_flush(this);
    return;
  }
  
  if (steg->transmit(chaff) != TRANSMIT_GOOD)
    conn_do_flush(this);

  evbuffer_free(chaff);
}





bool
chop_conn_t::must_send_p() const
{
  return must_send_timer && evtimer_pending(must_send_timer, 0);
}

/* static */ void
chop_conn_t::must_send_timeout(evutil_socket_t, short, void *arg)
{
  static_cast<chop_conn_t *>(arg)->send(2);
}


