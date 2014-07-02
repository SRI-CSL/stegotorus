
# Copyright 2011 Nick Mathewson, George Kadianakis
# Copyright 2011, 2012 SRI International
# See LICENSE for other credits and copying information

PROJECT_GIT_ORIG:=$(shell git config --get remote.origin.url 2>/dev/null || echo "unknownGITorigin")
PROJECT_GIT_BRCH:=$(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknownGITbranch")
PROJECT_GIT_HASH:=$(shell git log --pretty=format:'%H' -n 1 2>/dev/null || echo "unknownGIThash")
PROJECT_GIT_TIME:=$(shell git log --pretty=format:'%ci' -n 1 2>/dev/null || echo "unknownGITtime")

ACLOCAL_AMFLAGS = -I config-aux --install

#please note that the 32 bit time is needed for consistency inside the mingw64 build  
AM_CXXFLAGS = -g -Werror -Wall -Wextra -Wformat=2 -Weffc++ -fstack-protector-all -D_USE_32BIT_TIME_T


AM_CPPFLAGS = -I. -I$(srcdir)/src -D_FORTIFY_SOURCE=2 $(lib_CPPFLAGS) $(ws32_CFLAGS) \
		-DPROJECT_GIT_ORIG='"$(PROJECT_GIT_ORIG)"' \
		-DPROJECT_GIT_BRCH='"$(PROJECT_GIT_BRCH)"' \
		-DPROJECT_GIT_HASH='"$(PROJECT_GIT_HASH)"' \
		-DPROJECT_GIT_TIME='"$(PROJECT_GIT_TIME)"'

noinst_LIBRARIES = libstegotorus.a
noinst_PROGRAMS  = unittests tltester
bin_PROGRAMS     = stegotorus

PROTOCOLS = \
	src/protocol/chop.cc \
	src/protocol/chop_circuit.cc \
	src/protocol/chop_conn.cc \
	src/protocol/chop_blk.cc \
	src/protocol/null.cc

STEGANOGRAPHERS = \
	src/steg/headers.cc \
	src/steg/shared.cc \
	src/steg/crypto.cc \
	src/steg/b64cookies.cc \
	src/steg/embed.cc \
	src/steg/http.cc \
	src/steg/http_server.cc \
	src/steg/http_client.cc \
	src/steg/rawSteg.cc \
	src/steg/jpegSteg.cc \
	src/steg/images.cc \
	src/steg/pdfs.cc \
	src/steg/jsonSteg.cc \
	src/steg/jsSteg.cc \
	src/steg/jsutil.cc \
	src/steg/jscomment.cc \
	src/steg/jsperturb.cc \
	src/steg/nosteg.cc \
	src/steg/nosteg_rr.cc \
	src/steg/payloads.cc \
	src/steg/pdfSteg.cc \
	src/steg/schemes.cc \
	src/steg/swfSteg.cc \
	src/steg/swfparse.cc


libstegotorus_a_SOURCES = \
	src/base64.cc \
	src/compression.cc \
	src/connections.cc \
	src/crypt.cc \
	src/modus_operandi.cc \
	src/mkem.cc \
	src/network.cc \
	src/protocol.cc \
	src/rng.cc \
	src/socks.cc \
	src/steg.cc \
	src/util.cc \
	src/strncasestr.cc \
	src/util-net.cc \
	$(PROTOCOLS) $(STEGANOGRAPHERS)

if WINDOWS
libstegotorus_a_SOURCES += src/subprocess-windows.cc
else
libstegotorus_a_SOURCES += src/subprocess-unix.cc
endif

nodist_libstegotorus_a_SOURCES = protolist.cc steglist.cc

stegotorus_SOURCES = \
	src/main.cc

stegotorus_LDADD = libstegotorus.a $(lib_LIBS)

# prevent stegotorus from being linked if s-a-g fails
# it is known that $(lib_LIBS) contains nothing that needs to be depended upon
stegotorus_DEPENDENCIES = libstegotorus.a 
# ian says: we have ditched this: stamp-audit-globals
# for the gitian build.

## payload trace generators

bin_PROGRAMS += pgen_fake
pgen_fake_SOURCES = \
	src/pgen_fake.cc \
	src/util.cc \
	src/rng.cc \
	src/base64.cc

pgen_fake_LDADD = $(libcrypto_LIBS) $(libz_LIBS) $(ws32_LIBS)

# pgen_pcap is only built if we have libpcap
if HAVE_PCAP
bin_PROGRAMS += pgen_pcap

pgen_pcap_SOURCES = \
	src/pgen_pcap.cc \
	src/strncasestr.cc \
	src/compression.cc \
	src/util.cc

pgen_pcap_LDADD = $(pcap_LIBS) $(lib_LIBS) $(libz_LIBS)
endif

UTGROUPS = \
	src/test/unittest_base64.cc \
	src/test/unittest_compression.cc \
	src/test/unittest_crypt.cc \
	src/test/unittest_pdfsteg.cc \
	src/test/unittest_socks.cc

unittests_SOURCES = \
	src/test/tinytest.cc \
	src/test/unittest.cc \
	$(UTGROUPS)

nodist_unittests_SOURCES = unitgrplist.cc

unittests_LDADD = libstegotorus.a $(lib_LIBS)

tltester_SOURCES = src/test/tltester.cc src/util.cc src/util-net.cc
tltester_LDADD   = $(libevent_LIBS) $(ws32_LIBS)

noinst_HEADERS = \
	src/base64.h \
	src/compression.h \
	src/connections.h \
	src/crypt.h \
	src/listener.h \
	src/mkem.h \
	src/pgen.h \
	src/protocol.h \
	src/rng.h \
	src/socks.h \
	src/subprocess.h \
	src/steg.h \
	src/steg/http.h \
	src/steg/http_server.h \
	src/steg/http_client.h \
	src/util.h \
	src/strncasestr.h \
	src/protocol/chop_circuit.h \
	src/protocol/chop_conn.h \
	src/protocol/chop_blk.h \
	src/steg/b64cookies.h \
	src/steg/crypto.h \
	src/steg/jsSteg.h \
	src/steg/jpegSteg.h \
	src/steg/images.h \
	src/steg/pdfs.h \
	src/steg/jsonSteg.h \
	src/steg/rawSteg.h \
	src/steg/jsutil.h \
	src/steg/payloads.h \
	src/steg/pdfSteg.h \
	src/steg/swfSteg.h \
	src/steg/schemes.h \
	src/test/tinytest.h \
	src/test/tinytest_macros.h \
	src/test/unittest.h

dist_noinst_SCRIPTS = \
	src/audit-globals.sh \
	src/genmodtable.sh \
	src/test/genunitgrps.sh

EXTRA_DIST = doc \
	src/test/itestlib.py \
	src/test/test_socks.py \
	src/test/test_tl.py

# Generated source files
CLEANFILES = protolist.cc steglist.cc unitgrplist.cc \
	stamp-protolist stamp-steglist stamp-unitgrplist \
	stamp-audit-globals

GMOD  = $(SHELL) $(srcdir)/src/genmodtable.sh
GUNIT = $(SHELL) $(srcdir)/src/test/genunitgrps.sh
AGLOB = $(SHELL) $(srcdir)/src/audit-globals.sh

AM_V_gs   = $(AM_V_gs_$(V))
AM_V_gs_  = $(AM_V_gs_$(AM_DEFAULT_VERBOSITY))
AM_V_gs_0 = @echo "  GEN     " $(patsubst stamp-%,%.cc,$@);

AM_V_ag   = $(AM_V_ag_$(V))
AM_V_ag_  = $(AM_V_ag_$(AM_DEFAULT_VERBOSITY))
AM_V_ag_0 = @echo "  AGLOB";

deb:
	@echo "Building Debian Package..."
	@dpkg-buildpackage -b -us -uc

protolist.cc: stamp-protolist ;
stamp-protolist: $(PROTOCOLS) Makefile src/genmodtable.sh
	$(AM_V_gs) $(GMOD) protolist.cc $(filter %.cc, $^)
	$(AM_V_at) touch stamp-protolist

steglist.cc: stamp-steglist ;
stamp-steglist: $(STEGANOGRAPHERS) Makefile src/genmodtable.sh
	$(AM_V_gs) $(GMOD) steglist.cc $(filter %.cc, $^)
	$(AM_V_at) touch stamp-steglist

unitgrplist.cc: stamp-unitgrplist ;
stamp-unitgrplist: $(UTGROUPS) Makefile src/test/genunitgrps.sh
	$(AM_V_gs) $(GUNIT) unitgrplist.cc $(filter %.cc, $^)
	$(AM_V_at) touch stamp-unitgrplist

if WINDOWS
# Can't do this check when compiling for Windows as
# Linux's nm does not understand PE and it then just fails
stamp-audit-globals: Makefile
	$(AM_V_at) touch stamp-audit-globals
else
stamp-audit-globals: src/audit-globals.sh Makefile \
  $(libstegotorus_a_OBJECTS) $(stegotorus_OBJECTS)
	$(AM_V_ag) $(AGLOB) $(libstegotorus_a_OBJECTS) $(stegotorus_OBJECTS)
	$(AM_V_at) touch stamp-audit-globals
endif

# Testing
check-local:
	@echo --- Unit tests ---
	$(AM_V_at) ./unittests
if INTEGRATION_TESTS
	@echo --- Integration tests ---
	@set -ex; if [ ! -e traces ]; then \
	  if [ -e $(srcdir)/../steg-traces ]; then \
	    ln -s $(srcdir)/../steg-traces traces; \
	  elif [ -e $(srcdir)/traces ]; then \
	    ln -s $(srcdir)/traces traces; \
	  else \
	    mkdir traces && touch traces/.faked && ./pgen_fake; \
	  fi; \
	fi
	$(AM_V_at) $(PYTHON) -m unittest discover -s $(srcdir)/src/test -p 'test_*.py' -v
else
	@echo !!! Integration tests skipped !!!
endif

if INTEGRATION_TESTS
clean-local:
	[ ! -f traces/.faked ] || rm -r traces
endif
