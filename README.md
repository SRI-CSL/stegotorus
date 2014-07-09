StegoTorus
==========

Welcome to StegoTorus by SRI International (http://www.sri.com)

What is this?
-------------

Please see *"StegoTorus: A Camouflage Proxy for the Tor Anonymity System"*
for a detailed explanation on what this tool does and how it does it.
A copy can be found here: 
```
https://github.com/SRI-CSL/stegotorus/blob/master/doc/stegotorus.pdf?raw=true
```


General Compilation
-------------------

Prepare the raw git repository first and generate configure and Makefile:
```
autoreconf -i
./configure --enable-silent-rules
```

To compile manually:
```
make
```

Debian
------

To make a Debian package:
```
make deb
```

This will likely ask for various packages to be installed that are needed for compilation.

Mac OS X
--------

Install homebrew (if you do not have it yet):
```
ruby -e "$(curl -fsSL https://raw.github.com/mxcl/homebrew/go)"
```

Install dependencies:
```
brew install autoconf automake cmake docbook jansson libevent libtool openssl pkg-config readline tor
```

Compile StegoTorus:
```
cd stegotorus
autoreconf -i
./configure --enable-silent-rules libcrypto_CFLAGS=-I/usr/local/opt/openssl/include libcrypto_LIBS="-L/usr/local/opt/openssl/lib/ -lssl -lcrypto" libz_CFLAGS=-I/usr/include/ libz_LIBS="-L/usr/lib -lz" libjansson_CFLAGS=-I/usr/local/opt/jansson/include CFLAGS=-Wno-format-nonliteral
make
```

Note that on OS X 10.9 `libz` is new enough, hence why we point it there, we disable `-Wno-format-nonliteral` as we have code that does this, might want to properly solve this by adding the relevant pragmas that indicate that these strings need format checking though.

Windows
-------

Cross-compilation happens from a Debian/Ubuntu host.

Just run:
```
./cross-compile
```
and all should get arranged. This fetches and uses MXE for cross-compilation.

