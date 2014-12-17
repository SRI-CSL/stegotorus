Building StegoTorus on Darwin
==========

We describe the build process for a clean (modulo XCode, developer commandline tools,
emacs, xquartz, iterm2, and homebrew) install of `Mac OS X 10.9.5`.

We use clang++.


  1. Install the prerequisites:

  ```
>brew install git autoconf automake libjpeg pkg-config openssl libevent jansson
  ```
  
(if libevent fails to "link" try changing the ownership on /usr/local/lib/pkgconfig)

  2. Clone the repositories.
  
  ```
>git clone https://github.com/SRI-CSL/jel.git
>git clone https://github.com/SRI-CSL/stegotorus.git
  ```

  3. Build and install jel

  ```
>cd jel
>autoreconf -i
>./configure --enable-silent-rules
>make
>sudo make install
  ```


  4. Build StegoTorus


  ```
>cd stegotorus
>autoreconf -i
  ```


Overide apple's deprecation of openssl:

  ```
>export libcrypto_LIBS="-L/usr/local/opt/openssl/lib -lcrypto"
>export libcrypto_CFLAGS=-I/usr/local/opt/openssl/include
  ```

  ```
>./configure --enable-silent-rules
>make
  ```


  5. Testing StegoTorus

    1. Install the prerequisites

      ```
>brew install tor
      ```


    2. Make sure you can bootstrap tor:

      ```
>cd stegotorus
>tor -f data/torrc
      ```

     If this bootstrap OK, then kill tor, and remove the cache:

      ```
>rm -rf ~/.tor
      ```

    3. Now in two windows start stegotorus

      ```
>./modus_operandi/start-client-vm06
      ```

     and then in the other window, start tor, note we are using a different
configuration file.

      ```
>tor -f data/stegotorrc
      ```

    This should bootstrap but will no doubt be slower than bootstrapping
directly.








