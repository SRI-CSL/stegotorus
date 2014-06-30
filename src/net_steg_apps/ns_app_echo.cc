/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include <execinfo.h>
     
#include "util.h"
#include "connections.h"
#include "protocol.h"

#include <event2/buffer.h>
#include <event2/event.h>

#include "steg.h"

#include "listener.h"
#include <event2/listener.h>
#include <errno.h>

struct evbuffer *app_evbuf_in  = NULL;
struct evbuffer *app_evbuf_out = NULL;


// protocol module for the network steg library (nsl)
namespace {

  struct nsl_config_t : config_t
  {
    struct evutil_addrinfo *listen_addr;
    struct evutil_addrinfo *target_addr;

    // SC: steg
    steg_config_t *steg_targets;

    // adapted from CONFIG_DECLARE_METHODS
    nsl_config_t();
    virtual ~nsl_config_t();
    virtual const char *name() const;
    virtual bool init(int n_opts, const char *const *opts);
    virtual evutil_addrinfo *get_listen_addrs(size_t n) const;
    virtual evutil_addrinfo *get_target_addrs(size_t n) const;
    virtual const steg_config_t *get_steg(size_t n) const;
    virtual conn_t *conn_create(size_t index);
    //
    virtual circuit_t *circuit_create(size_t index);
  };


  struct nsl_conn_t : conn_t
  {
    nsl_config_t *config;

    // SC: steg
    steg_t *steg;
    struct evbuffer *recv_pending;

    // adapted from CONN_DECLARE_METHODS
    nsl_conn_t();
    virtual ~nsl_conn_t();
    virtual void close();
    // virtual circuit_t *circuit() const; 
    virtual int  handshake();
    virtual int  recv();
    virtual int  recv_eof();
    virtual void expect_close();
    virtual void cease_transmission();
    virtual void transmit_soon(unsigned long timeout);
    // 
    virtual int maybe_open_upstream();
  };

}



// adapted from PROTO_DEFINE_MODULE
const char *nsl_config_t::name() const
  { return "nsl"; }

static config_t * nsl_config_create(int n_opts, const char *const *opts)
  { nsl_config_t *s = new nsl_config_t();
    if (s->init(n_opts, opts))
      return s;
    delete s;
    return 0;
  }

extern const proto_module p_mod_nsl = {
    "nsl", nsl_config_create,
};




nsl_config_t::nsl_config_t()
{
}

nsl_config_t::~nsl_config_t()
{
  if (this->listen_addr)
    evutil_freeaddrinfo(this->listen_addr);
  if (this->target_addr)
    evutil_freeaddrinfo(this->target_addr);
}

circuit_t *
nsl_config_t::circuit_create(size_t index)
{
  return NULL;
}


bool
nsl_config_t::init(int n_options, const char *const *options)
{
  const char* defport;

  // SC: two arguments: mode, address:port
  if (n_options != 2)
    goto usage;

  if (!strcmp(options[0], "client")) {
    this->mode = LSN_SIMPLE_CLIENT;
  } else if (!strcmp(options[0], "server")) {
    defport = "11253"; /* 2bf5 */
    this->mode = LSN_SIMPLE_SERVER;
  } else
    goto usage;

  this->listen_addr = NULL;
  this->target_addr = NULL;
  if (this->mode == LSN_SIMPLE_SERVER) {
    this->listen_addr = resolve_address_port(options[1], 1, 1, defport);
    if (!this->listen_addr)
      goto usage;
  } else {  // this->mode == LSN_SIMPLE_CLIENT
    this->target_addr = resolve_address_port(options[1], 1, 0, NULL);
    if (!this->target_addr)
      goto usage;
  }

  steg_targets = steg_new("http", this);

  return true;

 usage:
  log_warn("network steg interface config syntax:\n"
           "\tserver <listen_address> | client <target_address>\n"
           "\t\tlisten_address, or target_address ~ host:port.\n"
           "Examples:\n"
           "\tclient 192.168.1.99:11253\n"
           "\tserver 192.168.1.99:11253");
  return false;
}


/** Retrieve the 'n'th set of listen addresses for this configuration. */
struct evutil_addrinfo *
nsl_config_t::get_listen_addrs(size_t n) const
{
  if (n > 0)
    return 0;
  return this->listen_addr;
}

/* Retrieve the target address for this configuration. */
struct evutil_addrinfo *
nsl_config_t::get_target_addrs(size_t n) const
{
  if (n > 0)
    return 0;
  return this->target_addr;
}


/*
  This is called everytime we get a connection.
*/

conn_t *
nsl_config_t::conn_create(size_t)
{
  nsl_conn_t *conn = new nsl_conn_t;
  conn->config = this;
  conn->steg = steg_targets->steg_create(conn);
  if (!conn->steg) {
    free(conn);
    return 0;
  }

  conn->recv_pending = evbuffer_new();
  return conn;
}

nsl_conn_t::nsl_conn_t()
{
}

nsl_conn_t::~nsl_conn_t()
{
  if (steg)
    delete steg;
  evbuffer_free(recv_pending);
}

void
nsl_conn_t::close()
{
  conn_t::close();
}

/** No handshake */
int
nsl_conn_t::handshake()
{
  return 0;
}

/** Receive data from connection SOURCE */
int
nsl_conn_t::recv()
{
  int result;

  if (steg) {
    log_debug ("nsl_conn_t::recv() calling steg %s receive", steg->cfg()->name());
  }

  log_debug(this, "receiving %lu bytes",
            (unsigned long)evbuffer_get_length(this->inbound()));
 
  result = steg->receive(app_evbuf_in);

  log_debug("nsl_conn_t::recv() returns %d", result);
  log_debug("steg->receive got %lu bytes",
            (unsigned long)evbuffer_get_length(app_evbuf_in));

  if (result) {
    return 0;
  } else {
    if (evbuffer_get_length(app_evbuf_in) == 0) return 0;
    else return 1; 
  }
}

/** Receive EOF from connection SOURCE */
int
nsl_conn_t::recv_eof()
{
  return 0;
}

// CONFIG_STEG_STUBS(nsl);
const steg_config_t *nsl_config_t::get_steg(size_t) const { return 0; }


// CONN_STEG_STUBS(nsl);
void nsl_conn_t::expect_close()
{ 
  // print_trace();
  log_debug(this, "steg stub called: expect_close"); 
}

void nsl_conn_t::cease_transmission()
{ 
  log_debug(this, "steg stub called: cease_transmission");
}

void nsl_conn_t::transmit_soon(unsigned long)
{ 
  log_debug(this, "steg stub called: transmit_soon"); 
}


int nsl_conn_t::maybe_open_upstream()
{
  log_debug(this, "steg stub called: maybe_open_upstream");
  return 0;
}




static void
server_read_cb(struct bufferevent *bev, void *arg)
{
  nsl_conn_t *down = (nsl_conn_t *)arg;
  int result;
  steg_t *steg;

  down->ever_received = 1;

  log_debug(down, "%lu bytes available",
            (unsigned long)evbuffer_get_length(bufferevent_get_input(bev)));

  result = down->recv();

  if (result) {
    steg = down->steg;

    fprintf(stderr, "server received: [");
    // displaying the data received
    char my_buf[1024];
    int n;
    for (int i=0; i<1024; i++) my_buf[i] = 0;
    while ((n = evbuffer_remove(app_evbuf_in, my_buf, sizeof(my_buf))) > 0) {
      fwrite(my_buf, 1, n, stderr);
    }
    fprintf(stderr, "]\n");

    size_t mlen;
    mlen = (unsigned)strlen(my_buf);

    // echo data back to the client
    int result2;
    result2 = evbuffer_add(app_evbuf_out, my_buf, mlen);
    if (result2) {
        log_abort("evbuffer_add to app_evbuf_out failed");
    }

    // calling steg->transmit_room()
    // calling steg->transmit
    size_t avail_space; 
    avail_space = steg->transmit_room(mlen, 1, mlen); 
    log_debug("mlen = %lu", mlen);
    struct evbuffer *obuf;
    if (avail_space >= mlen) {
        obuf = down->outbound();
        // result2 = evbuffer_add(obuf, my_buf, mlen);
        // printf("evbuffer_add returned %d\n", result2);
        // result2 = bufferevent_flush(down->buffer, EV_WRITE, BEV_FINISHED);
        // printf("bufferevent_flush returned %d\n", result2);
        result2 = steg->transmit(app_evbuf_out);
        log_debug("transmit returned %d", result2);
    } else {
        log_warn("insufficient space to send msg back to the client");
    }

    conn_do_flush(down);

    // down->close();
  }
}



static void 
server_flush_cb(struct bufferevent *bev, void *arg)
{
  conn_t *conn = (conn_t *)arg;
  size_t remain = evbuffer_get_length(bufferevent_get_output(bev));

  log_debug("inside server_flush_cb");

  log_debug(conn, "%lu bytes still to transmit%s%s%s%s%s",
            (unsigned long)remain,
            conn->connected ? "" : " (not connected)",
            conn->pending_write_eof ? " (reached EOF)" : "",
            conn->write_eof ? " (sent EOF)" : "",
            conn->read_eof ? " (received EOF)" : "",
            conn->ever_received ? "" : " (never received)");

  if (remain == 0 && ((conn->pending_write_eof && conn->connected)
                      || conn->ever_received)) {
    conn->write_eof = true;
    if (conn->read_eof && conn->write_eof)
      conn->close();
  }
}



static void
server_event_cb(struct bufferevent *bev, short what, void *arg)
{
  conn_t *conn = (conn_t *)arg;

  log_debug("server_event_cb entry");

  log_debug(conn, "what=%04hx enabled=%x inbound=%lu outbound=%lu",
            what, bufferevent_get_enabled(bev),
            (unsigned long)evbuffer_get_length(bufferevent_get_input(bev)),
            (unsigned long)evbuffer_get_length(bufferevent_get_output(bev)));

  if (what & (BEV_EVENT_ERROR|BEV_EVENT_EOF|BEV_EVENT_TIMEOUT)) {

    if (what & BEV_EVENT_ERROR) {
      log_info(conn, "network error in %s: %s",
               (what & BEV_EVENT_READING) ? "read" : "write",
               evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    } else if (what & BEV_EVENT_EOF) {
      log_info(conn, "%s",
               (what & BEV_EVENT_READING)
               ? "EOF from peer"
               : "further transmissions to peer squelched");
    } else if (what & BEV_EVENT_TIMEOUT) {
      log_warn(conn, "%s timed out",
               (what & BEV_EVENT_READING) ? "read" : "write");
    }

    if (what == (BEV_EVENT_EOF|BEV_EVENT_READING)) {
      /* Peer is done sending us data. */
      conn->recv_eof();
      conn->read_eof = true;
      if (conn->read_eof && conn->write_eof)
        conn->close();
    } else {
      conn->close();
    }
  } else {
    /* We should never get BEV_EVENT_CONNECTED here.
       Ignore any events we don't understand. */
    if (what & BEV_EVENT_CONNECTED) {
      log_abort(conn, "double connection event");
    }
  }
}


static void
client_read_cb(struct bufferevent *bev, void *arg)
{

  log_debug("inside client_read_cb");

  nsl_conn_t *down = (nsl_conn_t *)arg;

  down->ever_received = 1;

  log_debug(down, "%lu bytes available",
            (unsigned long)evbuffer_get_length(bufferevent_get_input(bev)));

  steg_t *steg;
  if (down->recv()) {

    steg = down->steg;
    fprintf(stderr, "client received: [");
    // displaying the data received
    char my_buf[1024];
    int n;
    for (int i=0; i<1024; i++) my_buf[i] = 0;
    while ((n = evbuffer_remove(app_evbuf_in, my_buf, sizeof(my_buf))) > 0) {
      fwrite(my_buf, 1, n, stderr);
    }
    fprintf(stderr, "]\n");

    down->close();
  }

}


static void
client_event_cb(struct bufferevent *bev, short events, void *ptr)
{

  if (events & BEV_EVENT_CONNECTED) {
    log_debug("client_event_cb: Connect okay.");
  } else if (events & (BEV_EVENT_ERROR|BEV_EVENT_EOF)) {
    if (events & BEV_EVENT_ERROR) {
      log_debug("client_event_cb: BEV_EVENT_ERROR");
    }
    log_debug("client_event_cb: Closing");
    bufferevent_free(bev);
  }
}


static void
client_flush_cb(struct bufferevent *bev, void *arg)
{

  conn_t *conn = (conn_t *)arg;
  size_t remain = evbuffer_get_length(bufferevent_get_output(bev));
  log_debug(conn, "%lu bytes still to transmit%s%s%s%s%s",
            (unsigned long)remain,
            conn->connected ? "" : " (not connected)",
            conn->pending_write_eof ? " (reached EOF)" : "",
            conn->write_eof ? " (sent EOF)" : "",
            conn->read_eof ? " (received EOF)" : "",
            conn->ever_received ? "" : " (never received)");

  if (remain == 0 && ((conn->pending_write_eof && conn->connected)
                      || conn->ever_received)) {
    conn->write_eof = true;
//    if (conn->read_eof && conn->write_eof)
//      conn->close();
  }
}



static void
accept_error_cb(struct evconnlistener *listener, void *ctx)
{
  struct event_base *base = evconnlistener_get_base(listener);
  int err = EVUTIL_SOCKET_ERROR();
  fprintf(stderr, "Got an error %d (%s) on the listener. "
          "Shutting down.\n", err, evutil_socket_error_to_string(err));

  event_base_loopexit(base, NULL);
}




static void
server_listener_cb(struct evconnlistener * listener, evutil_socket_t fd,
                   struct sockaddr *peeraddr, int peerlen,
                   void *closure)
{
  listener_t *lsn = (listener_t *)closure;
  char *peername = printable_address(peeraddr, peerlen);
  struct bufferevent *buf;
  conn_t *conn;

  log_assert(lsn->cfg->mode == LSN_SIMPLE_SERVER);
  log_info("%s: new connection to server from %s", lsn->address, peername);

  log_debug("server_listener_cb: new connection to server [%s] from [%s]", lsn->address, peername);

  buf = bufferevent_socket_new(lsn->cfg->base, fd, BEV_OPT_CLOSE_ON_FREE);
  if (!buf) {
    log_warn("%s: failed to create buffer for new connection from %s",
             lsn->address, peername);
    evutil_closesocket(fd);
    free(peername);
    return;
  }

  conn = (lsn->cfg)->conn_create(lsn->index);
  if (!conn) {
    log_warn("%s: failed to create connection structure for %s",
             lsn->address, peername);
    bufferevent_free(buf);
    free(peername);
    return;
  }
  conn->buffer = buf;
  conn->connected = 1;

  bufferevent_setcb(buf, server_read_cb, server_flush_cb, server_event_cb, conn);
  bufferevent_enable(conn->buffer, EV_READ|EV_WRITE);

}




int
main (int argc, char *argv[])
{
  struct event_config *evcfg;
  config_t* proto_cfg = NULL;

  struct nsl_config_t pc;
  struct nsl_config_t *pcp;

  char** config_argv;
  int config_argc;

  int res;
  res = log_set_method(LOG_METHOD_STDERR, NULL);
  if (res) {
    fprintf(stderr, "DBG: log_set_method fails\n");
  }

  // set min log severity
  char severity[] = "warn";  // options: "debug", "info", "warn", "error"
  // char severity[] = "debug";  // options: "debug", "info", "warn", "error"
  res = log_set_min_severity(severity);
  if (res) {
    fprintf(stderr, "DBG: log_set_min_severity fails\n");
  }

  app_evbuf_in  = evbuffer_new();
  app_evbuf_out = evbuffer_new();
  if (!app_evbuf_in || !app_evbuf_out) {
    log_warn("evbuffer_new fails\n");
    return 1;
  }

  pcp = &pc;
  config_argc = argc - 1;
  config_argv = ++argv;

  if (! pcp->init(config_argc, config_argv)) {
    log_warn("nsl_config init failed\n");
    return 1;
  }

  evcfg = event_config_new();
  if (!evcfg) {
    log_abort("Failed to initialize networking (evcfg)");
  }

  struct event_base *the_event_base = event_base_new_with_config(evcfg);
  if (!the_event_base) {
    log_abort("failed to initialize networking (evbase)");
  }
  

  const unsigned flags =
    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE;
  listener_t *lsn;
  struct evutil_addrinfo *addrs;

  pcp->base = the_event_base;
  if (pcp->mode == LSN_SIMPLE_SERVER) {
    /* SC: we only use 1 listen addr; the index arg is not needed here */
    addrs = pcp->get_listen_addrs(0);
    lsn = (listener_t *)xzalloc(sizeof(listener_t));
    lsn->cfg = pcp;
    lsn->address = printable_address(addrs->ai_addr, addrs->ai_addrlen);
    lsn->index = 0;
    lsn->listener =
      evconnlistener_new_bind(the_event_base, server_listener_cb, lsn, flags, -1,
                              addrs->ai_addr, addrs->ai_addrlen);

    if (!lsn->listener) {
      perror("Couldn't create listener");
      return 1;
    }
    evconnlistener_set_error_cb(lsn->listener, accept_error_cb);

    fprintf(stderr, "*** server ready to receive data\n");
  } else { // pcp->mode == LSN_SIMPLE_CLIENT

    nsl_conn_t *conn_client;
    size_t conn_num = 0;

    int i, result, msg_len;
    msg_len = 80;
    char msg[msg_len+1];

    for (i=0; i < msg_len; i++)
      msg[i] = 'A';
    msg[msg_len] = 0;

    struct bufferevent *buf;
    char *peername;

    addrs = pcp->get_target_addrs(0);
    peername = printable_address(addrs->ai_addr, addrs->ai_addrlen);

    conn_client = (nsl_conn_t *) pcp->conn_create(conn_num);

    buf = bufferevent_socket_new(pcp->base, -1, BEV_OPT_CLOSE_ON_FREE);
    if (!buf) {
      log_warn("unable to create outbound socket buffer");
      return 1;
    }

    bufferevent_setcb(buf, client_read_cb, client_flush_cb, client_event_cb, conn_client);
    bufferevent_enable(buf, EV_READ|EV_WRITE);

    size_t space;
    int j;

    log_debug("calling conn_client->steg->transmit_room for %d", msg_len);
    space = conn_client->steg->transmit_room(msg_len, 1, msg_len);
    log_debug("transmit_room returned %lu", space);
    if (space >= msg_len) {
      result = evbuffer_add(app_evbuf_out, msg, (size_t) msg_len);
      if (result) {
        log_abort("evbuffer_add to app_evbuf_out failed");
      }
      log_debug("app_evbuf_out has length %lu", evbuffer_get_length(app_evbuf_out));
    }

    if (bufferevent_socket_connect(buf,
                                   addrs->ai_addr,
                                   addrs->ai_addrlen) >= 0) {
      conn_client->buffer = buf;
      conn_client->peername = peername;
    } else {
      free(peername);
      return 1;
    }

    log_debug("calling transmit to send msg of length %d", msg_len);
    log_debug("msg content: [%s]", msg);

    result = conn_client->steg->transmit(app_evbuf_out);
    log_debug("conn_client->steg->transmit returned %d", result);

    conn_do_flush(conn_client);

  }


  event_base_dispatch(the_event_base);

  return 0;

}
