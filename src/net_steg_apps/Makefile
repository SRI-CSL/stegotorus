
# Note: The following configuration was tested on Mac OS X 10.8.4
pkgdir        = /Users/alice/git/stegotorus
pkgsrcdir     = ${pkgdir}/src
stegsrcdir    = ${pkgdir}/src/steg

pkgincludedir = /opt/local/include
pkglibdir     = /opt/local/lib

CFLAGS = -I$(pkgincludedir) -I$(pkgdir) -I$(pkgsrcdir) -I$(stegsrcdir) -std=c++11

objects = headers.o shared.o util.o util-net.o protocol.o steg.o socks.o \
          connections.o network.o protolist_app.o steglist_app.o \
          rng.o b64cookies.o cookies.o compression.o payloads.o base64.o jsutil.o \
          swfSteg.o pdfSteg.o jsSteg.o http.o

ns_app_echo : $(objects) ns_app_echo.cc
	g++ $(CFLAGS) \
	-DSTEG_TRACES_DIR=\"../../traces/\" \
	-L$(pkglibdir) -levent -lz -lcrypto \
	-o ns_app_echo \
	$(objects) \
	ns_app_echo.cc

headers.o : $(stegsrcdir)/headers.cc $(stegsrcdir)/headers.h $(pkgsrcdir)/util.h $(pkgsrcdir)/base64.h $(stegsrcdir)/b64cookies.h
	g++ $(CFLAGS) -c $(stegsrcdir)/headers.cc

shared.o : $(stegsrcdir)/shared.cc $(stegsrcdir)/shared.h $(stegsrcdir)/headers.h $(pkgsrcdir)/util.h $(pkgsrcdir)/base64.h $(stegsrcdir)/b64cookies.h $(pkgsrcdir)/compression.h $(stegsrcdir)/payloads.h
	g++ $(CFLAGS) -c $(stegsrcdir)/shared.cc

util.o : $(pkgsrcdir)/util.cc $(pkgsrcdir)/util.h $(pkgsrcdir)/connections.h
	g++ $(CFLAGS) -c $(pkgsrcdir)/util.cc

util-net.o : $(pkgsrcdir)/util-net.cc $(pkgsrcdir)/util.h
	g++ $(CFLAGS) -c $(pkgsrcdir)/util-net.cc

protocol.o : $(pkgsrcdir)/protocol.cc $(pkgsrcdir)/protocol.h $(pkgsrcdir)/util.h
	g++ $(CFLAGS) -c $(pkgsrcdir)/protocol.cc

steg.o : $(pkgsrcdir)/steg.cc $(pkgsrcdir)/steg.h $(pkgsrcdir)/util.h
	g++ $(CFLAGS) -c $(pkgsrcdir)/steg.cc

socks.o : $(pkgsrcdir)/socks.cc $(pkgsrcdir)/socks.h $(pkgsrcdir)/util.h
	g++ $(CFLAGS) -c $(pkgsrcdir)/socks.cc

connections.o : $(pkgsrcdir)/connections.cc $(pkgsrcdir)/connections.h $(pkgsrcdir)/util.h $(pkgsrcdir)/protocol.h $(pkgsrcdir)/socks.h
	g++ $(CFLAGS) -DNET_STEG_APP -c $(pkgsrcdir)/connections.cc

network.o : $(pkgsrcdir)/network.cc $(pkgsrcdir)/util.h $(pkgsrcdir)/listener.h $(pkgsrcdir)/connections.h $(pkgsrcdir)/protocol.h $(pkgsrcdir)/socks.h
	g++ $(CFLAGS) -DNET_STEG_APP -c $(pkgsrcdir)/network.cc

protolist_app.o : protolist_app.cc
	g++ -c -DNET_STEG_APP protolist_app.cc

steglist_app.o : steglist_app.cc
	g++ -c -DNET_STEG_APP steglist_app.cc

rng.o : $(pkgsrcdir)/rng.cc $(pkgsrcdir)/rng.h $(pkgsrcdir)/util.h
	g++ $(CFLAGS) -c $(pkgsrcdir)/rng.cc

b64cookies.o : $(stegsrcdir)/b64cookies.cc $(stegsrcdir)/b64cookies.h $(pkgsrcdir)/util.h
	g++ $(CFLAGS) -c $(stegsrcdir)/b64cookies.cc

cookies.o : $(stegsrcdir)/cookies.cc $(stegsrcdir)/cookies.h $(pkgsrcdir)/util.h
	g++ $(CFLAGS) -c $(stegsrcdir)/cookies.cc

compression.o : $(pkgsrcdir)/compression.cc $(pkgsrcdir)/compression.h $(pkgsrcdir)/util.h
	g++ $(CFLAGS) -c $(pkgsrcdir)/compression.cc

payloads.o : $(stegsrcdir)/payloads.cc $(stegsrcdir)/payloads.h $(pkgsrcdir)/util.h $(stegsrcdir)/headers.h $(pkgsrcdir)/compression.h $(stegsrcdir)/swfSteg.h
	g++ $(CFLAGS) -c $(stegsrcdir)/payloads.cc

base64.o : $(pkgsrcdir)/base64.cc $(pkgsrcdir)/base64.h
	g++ $(CFLAGS) -c $(pkgsrcdir)/base64.cc

swfSteg.o : $(stegsrcdir)/swfSteg.cc $(stegsrcdir)/swfparse.cc $(stegsrcdir)/swfSteg.h $(pkgsrcdir)/util.h $(pkgsrcdir)/compression.h $(pkgsrcdir)/connections.h $(stegsrcdir)/payloads.h $(pkgsrcdir)/base64.h $(stegsrcdir)/headers.h
	g++ $(CFLAGS) -c $(stegsrcdir)/swfSteg.cc

pdfSteg.o : $(stegsrcdir)/pdfSteg.cc $(stegsrcdir)/pdfSteg.h $(pkgsrcdir)/util.h $(pkgsrcdir)/connections.h $(stegsrcdir)/payloads.h $(pkgsrcdir)/compression.h $(stegsrcdir)/headers.h
	g++ $(CFLAGS) -c $(stegsrcdir)/pdfSteg.cc

jsutil.o : $(stegsrcdir)/jsutil.cc $(pkgsrcdir)/util.h $(stegsrcdir)/payloads.h $(stegsrcdir)/jsutil.h
	g++ $(CFLAGS) -c $(stegsrcdir)/jsutil.cc

jsSteg.o : $(stegsrcdir)/jsSteg.cc $(stegsrcdir)/jsSteg.h $(pkgsrcdir)/util.h $(pkgsrcdir)/connections.h $(stegsrcdir)/payloads.h $(pkgsrcdir)/compression.h $(stegsrcdir)/headers.h $(stegsrcdir)/cookies.h $(stegsrcdir)/shared.h $(stegsrcdir)/jsutil.h
	g++ $(CFLAGS) -c $(stegsrcdir)/jsSteg.cc


http.o : $(stegsrcdir)/http.cc $(pkgsrcdir)/util.h $(pkgsrcdir)/connections.h $(stegsrcdir)/payloads.h $(stegsrcdir)/headers.h \
         $(stegsrcdir)/cookies.h $(stegsrcdir)/shared.h $(pkgsrcdir)/protocol.h $(pkgsrcdir)/steg.h $(pkgsrcdir)/rng.h $(stegsrcdir)/jsutil.h \
         $(stegsrcdir)/swfSteg.h $(stegsrcdir)/pdfSteg.h $(stegsrcdir)/jsSteg.h $(pkgsrcdir)/base64.h $(stegsrcdir)/b64cookies.h
	g++ $(CFLAGS) -DSTEG_TRACES_DIR=\"../../traces/\" -c $(stegsrcdir)/http.cc


clean :
	rm $(objects) ns_app_echo
