Building StegoTorus on Linux
==========

We describe the build process for a clean (modulo apt-get install emacs openssh-server)
install on ubuntu-12.04.5-server-amd64.

We use g++ but clang++ should also work fine (after it is installed).


1. Install the prerequisites:

>sudo apt-get install git autoconf libtool libjpeg-dev make g++ pkg-config libssl-dev libevent-dev libjansson-dev


2. Clone the repositories.

>git clone https://github.com/SRI-CSL/jel.git

>git clone https://github.com/SRI-CSL/stegotorus.git


3. Build and install jel


>cd jel

>autoreconf -i

>./configure --enable-silent-rules

>make

>sudo make install


4. Build StegoTorus

>cd stegotorus

>autoreconf -i

>./configure --enable-silent-rules

>make










