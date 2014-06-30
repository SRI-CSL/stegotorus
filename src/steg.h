/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */
#ifndef STEG_H
#define STEG_H

#include "protocol.h"

#include "cpp.h"


/** A 'steg_config_t' is analogous to a 'config_t' (see protocol.h);
    it defines cross-connection state for a steganography module.
    (A 'config_t' may be associated with several 'steg_config_t's.)

    A steganography module must define a private subclass of this
    type, that implements all the methods below, plus a descendant
    constructor.  The subclass must have the name MODULE_steg_config_t,
    where MODULE is the module name you use in STEG_DEFINE_MODULE.
    It should be declared inside an anonymous namespace.
    Use STEG_CONFIG_DECLARE_METHODS in the declaration. */

class steg_t;


class steg_config_t
{

 public:

  config_t *cfg;

 steg_config_t(config_t *c) : cfg(NULL) { cfg = c; }

  virtual ~steg_config_t();

  /** Report the name of this steg module.  You do not have to define
      this method in your subclass, STEG_DEFINE_MODULE does it for you. */
  virtual const char *name() const = 0;

  /** Create an extended 'steg_t' object (see below) from this
      configuration, associated with connection CONN.  */
  virtual steg_t *steg_create(conn_t *conn) = 0;

  DISALLOW_COPY_AND_ASSIGN(steg_config_t);

};

/** A 'steg_t' object handles the actual steganography for one
    connection, and is responsible for tracking per-connection
    state for the cover protocol, if any.

    Again, a steganography module must define a private subclass of
    this type, that implements all of the methods below, plus a
    descendant constructor.  The subclass must have the name
    MODULE_steg_t, where MODULE is the module name you use in
    STEG_DEFINE_MODULE.  It should be declared inside an anonymous
    namespace.  Use STEG_DECLARE_METHODS in the declaration. */
class steg_t
{

 public:
  steg_t() {}

  virtual ~steg_t();

  /** Return the steg_config_t from which this steg_t was created. */
  virtual steg_config_t *cfg() = 0;

  /** The protocol using this steg module would like to transmit PREF
      bytes on your connection.  Return an adjusted number of bytes;
      you may adjust down to indicate that you cannot transmit all of
      the available data, or up to indicate that it should be padded.

      Returning zero indicates that your connection cannot transmit at
      all right now; if you do this, transmit() will not be called.
      Returning any nonzero value indicates that you want to transmit
      exactly that number of bytes.  The protocol may or may not call
      transmit() after you return a nonzero value, but if it does, it
      will provide the number of bytes you requested.

      If you return a nonzero value, it MUST be greater than or equal
      to MIN, and less than or equal to MAX.  PREF is guaranteed to be
      in this range already.  */
  virtual size_t transmit_room(size_t pref, size_t min, size_t max) = 0;

  /** Consume all of the data in SOURCE, disguise it, and write it to
      the outbound buffer for your connection. Return 0 on success, -1
      on failure. */
  virtual transmit_t transmit(struct evbuffer *source) = 0;

  /** Unmask as much of the data in your connection's inbound buffer
      as possible, and write it to DEST.  Return 0 on success, -1 on
      failure.  If more data needs to come over the wire before
      anything can be unmasked, that is *not* a failure condition;
      return 0, but do not consume any data or write anything to DEST.
      It is *preferable*, but not currently *required*, for this
      method to not consume any data or write anything to DEST in a
      failure situation. */
  virtual recv_t receive(struct evbuffer *dest) = 0;

  virtual void successful_reception() = 0; 
  virtual unsigned int corrupted_reception() = 0; 

  DISALLOW_COPY_AND_ASSIGN(steg_t);


};

/** STEG_DEFINE_MODULE defines an object with this type, plus the
    function that it points to; there is a table of all such objects,
    which generic code uses to know what steganography modules are
    available. */
struct steg_module
{
  /** Name of the steganography module. Must be a valid C identifier. */
  const char *name;

  /** Create an appropriate steg_config_t subclass for this module. */
  steg_config_t *(*new_)(config_t *cfg);
};

extern const steg_module *const supported_stegs[];

int steg_is_supported(const char *name);
steg_config_t *steg_new(const char *name, config_t *cfg);

/* Macros for use in defining steg modules. */

#define STEG_DEFINE_MODULE(mod)                         \
  /* new_ dispatchers */                                \
  static steg_config_t *mod##_new(config_t *cfg)        \
  { return new mod##_steg_config_t(cfg); }              \
                                                        \
  /* canned methods */                                  \
  const char *mod##_steg_config_t::name() const         \
  { return #mod; }                                      \
                                                        \
  /* module object */                                   \
  extern const steg_module s_mod_##mod = {              \
    #mod, mod##_new                                     \
  } /* deliberate absence of semicolon */

#define STEG_CONFIG_DECLARE_METHODS(mod)                \
  mod##_steg_config_t(config_t *);                      \
  virtual ~mod##_steg_config_t();                       \
  virtual const char *name() const;                     \
  virtual steg_t *steg_create(conn_t *)                 \
  /* deliberate absence of semicolon */

#define STEG_DECLARE_METHODS(mod)                       \
  virtual ~mod##_steg_t();                              \
  virtual steg_config_t *cfg();                         \
  virtual size_t transmit_room(size_t, size_t, size_t); \
  virtual transmit_t transmit(struct evbuffer *);              \
  virtual recv_t receive(struct evbuffer *);		\
  virtual void successful_reception();                  \
  virtual unsigned int corrupted_reception()

  /* deliberate absence of semicolon */

#endif
