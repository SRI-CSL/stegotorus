#!/bin/bash -e
#
# This is a simple wrapper script to call out to gitian and assemble
# a bundle based on gitian's output.

if [ -z "$1" ];
then
  VERSIONS_FILE=./versions
else
  VERSIONS_FILE=$1
fi

if ! [ -e $VERSIONS_FILE ]; then
  echo >&2 "Error: $VERSIONS_FILE file does not exist"
  exit 1
fi

. $VERSIONS_FILE

WRAPPER_DIR=$PWD
GITIAN_DIR=$PWD/../../gitian-builder
DESCRIPTOR_DIR=$PWD/descriptors/

if [ ! -f $GITIAN_DIR/bin/gbuild ];
then
  echo "Gitian not found. You need a Gitian checkout in $GITIAN_DIR"
  exit 1
fi

if [ -z "$NUM_PROCS" ];
then
  export NUM_PROCS=2
fi

if [ -z "$VM_MEMORY" ];
then
  export VM_MEMORY=2000
fi

./make-vms.sh

cd $GITIAN_DIR
export PATH=$PATH:$PWD/libexec

echo "pref(\"torbrowser.version\", \"$TORBROWSER_VERSION-MacOS\");" > $GITIAN_DIR/inputs/torbrowser.version
echo "$TORBROWSER_VERSION" > $GITIAN_DIR/inputs/bare-version
cp -a $WRAPPER_DIR/$VERSIONS_FILE $GITIAN_DIR/inputs/versions

cp -r $WRAPPER_DIR/build-helpers/* $GITIAN_DIR/inputs/
cp $WRAPPER_DIR/patches/* $GITIAN_DIR/inputs/

cd $WRAPPER_DIR/../Bundle-Data/
rm -f $GITIAN_DIR/inputs/tbb-docs.zip
$WRAPPER_DIR/build-helpers/dzip.sh $GITIAN_DIR/inputs/tbb-docs.zip ./Docs/
cp PTConfigs/mac/torrc-defaults-appendix $GITIAN_DIR/inputs/torrc-defaults-appendix-mac
cp PTConfigs/bridge_prefs.js $GITIAN_DIR/inputs/
cp mac-tor.sh $GITIAN_DIR/inputs/

cd mac
rm -f $GITIAN_DIR/inputs/mac-skeleton.zip
$WRAPPER_DIR/build-helpers/dzip.sh $GITIAN_DIR/inputs/mac-skeleton.zip .
cd ../mac-desktop.dmg
rm -f $GITIAN_DIR/inputs/dmg-desktop.tar.xz
$WRAPPER_DIR/build-helpers/dtar.sh $GITIAN_DIR/inputs/dmg-desktop.tar.xz .
cd ../mac-applications.dmg
rm -f $GITIAN_DIR/inputs/dmg-applications.tar-gz
$WRAPPER_DIR/build-helpers/dtar.sh $GITIAN_DIR/inputs/dmg-applications.tar.xz .

echo "Prepping stegotorus files"

if [ ! -f $GITIAN_DIR/inputs/sribundle.tar.gz ];
then
    cp -v $WRAPPER_DIR/sribundle.tar.gz  $GITIAN_DIR/inputs/
else
    rm -rf $GITIAN_DIR/inputs/sribundle
    echo "Stegotorus already prepped"
fi

cd $WRAPPER_DIR

# FIXME: Library function?
die_msg() {
  local msg="$1"; shift
  printf "\n\n$msg\n"
  exit 1
}

# Let's preserve the original $FOO for creating proper symlinks after building
# the utils both if we verify tags and if we don't.

LIBEVENT_TAG_ORIG=$LIBEVENT_TAG

if [ "z$VERIFY_TAGS" = "z1" ];
then
  ./verify-tags.sh $GITIAN_DIR/inputs $VERSIONS_FILE || die_msg "You should run 'make prep' to ensure your inputs are up to date"
  # If we're verifying tags, be explicit to gitian that we
  # want to build from tags.
  NSIS_TAG=refs/tags/$NSIS_TAG
  GITIAN_TAG=refs/tags/$GITIAN_TAG
  TORLAUNCHER_TAG=refs/tags/$TORLAUNCHER_TAG
  TORBROWSER_TAG=refs/tags/$TORBROWSER_TAG
  TORBUTTON_TAG=refs/tags/$TORBUTTON_TAG
  TOR_TAG=refs/tags/$TOR_TAG
  HTTPSE_TAG=refs/tags/$HTTPSE_TAG
  ZLIB_TAG=refs/tags/$ZLIB_TAG
  LIBEVENT_TAG=refs/tags/$LIBEVENT_TAG
  PYPTLIB_TAG=refs/tags/$PYPTLIB_TAG
  OBFSPROXY_TAG=refs/tags/$OBFSPROXY_TAG
  FLASHPROXY_TAG=refs/tags/$FLASHPROXY_TAG
fi

cd $GITIAN_DIR

if [ ! -f inputs/openssl-$OPENSSL_VER-mac32-utils.zip -o \
     ! -f inputs/libevent-${LIBEVENT_TAG_ORIG#release-}-mac32-utils.zip -o \
     ! -f inputs/gmp-$GMP_VER-mac32-utils.zip ];
then
  echo
  echo "****** Starting Utilities Component of Mac Bundle (1/5 for Max) ******"
  echo
  ./bin/gbuild -j $NUM_PROCS -m $VM_MEMORY --commit libevent=$LIBEVENT_TAG $DESCRIPTOR_DIR/mac/gitian-utils.yml
  if [ $? -ne 0 ];
  then
    #mv var/build.log ./utils-fail-mac.log.`date +%Y%m%d%H%M%S`
    exit 1
  fi

  cd inputs
  cp -a ../build/out/*-utils.zip .
  ln -sf openssl-$OPENSSL_VER-mac32-utils.zip openssl-mac32-utils.zip
  ln -sf libevent-${LIBEVENT_TAG_ORIG#release-}-mac32-utils.zip libevent-mac32-utils.zip
  ln -sf gmp-$GMP_VER-mac32-utils.zip gmp-mac32-utils.zip
  cd ..
  #cp -a result/utils-mac-res.yml inputs/
else
  echo
  echo "****** SKIPPING already built Utilities Component of Mac Bundle (1/5 for
  Mac) ******"
  echo
  # We might have built the utilities in the past but maybe the links are
  # pointing to the wrong version. Refresh them.
  cd inputs
  ln -sf openssl-$OPENSSL_VER-mac32-utils.zip openssl-mac32-utils.zip
  ln -sf libevent-${LIBEVENT_TAG_ORIG#release-}-mac32-utils.zip libevent-mac32-utils.zip
  ln -sf gmp-$GMP_VER-mac32-utils.zip gmp-mac32-utils.zip
  cd ..
fi

if [ ! -f inputs/tor-mac32-gbuilt.zip ];
then
  echo
  echo "****** Starting Tor Component of Mac Bundle (2/5 for Mac) ******"
  echo

  ./bin/gbuild -j $NUM_PROCS -m $VM_MEMORY --commit tor=$TOR_TAG $DESCRIPTOR_DIR/mac/gitian-tor.yml
  if [ $? -ne 0 ];
  then
    #mv var/build.log ./tor-fail-mac.log.`date +%Y%m%d%H%M%S`
    exit 1
  fi

  cp -a build/out/tor-mac*-gbuilt.zip inputs/
  #cp -a result/tor-mac-res.yml inputs/
else
  echo
  echo "****** SKIPPING already built Tor Component of Mac Bundle (2/5 for Mac) ******"
  echo
fi

if [ ! -f inputs/tor-browser-mac32-gbuilt.zip ];
then
  echo
  echo "****** Starting TorBrowser Component of Mac Bundle (3/5 for Mac) ******"
  echo

  ./bin/gbuild -j $NUM_PROCS -m $VM_MEMORY --commit tor-browser=$TORBROWSER_TAG $DESCRIPTOR_DIR/mac/gitian-firefox.yml
  if [ $? -ne 0 ];
  then
    #mv var/build.log ./firefox-fail-mac.log.`date +%Y%m%d%H%M%S`
    exit 1
  fi

  cp -a build/out/tor-browser-mac*-gbuilt.zip inputs/
  #cp -a result/torbrowser-mac-res.yml inputs/
else
  echo
  echo "****** SKIPPING already built TorBrowser Component of Mac Bundle (3/5 for Mac) ******"
  echo
fi

if [ ! -f inputs/pluggable-transports-mac32-gbuilt.zip ];
then
  echo
  echo "****** Starting Pluggable Transports Component of Mac Bundle (4/5 for Mac) ******"
  echo

  ./bin/gbuild -j $NUM_PROCS -m $VM_MEMORY --commit zlib=$ZLIB_TAG,jansson=$JANSSON_TAG,stegotorus=$STEGOTORUS_TAG,jel=$JEL_TAG,libevent=$LIBEVENT_TAG,pyptlib=$PYPTLIB_TAG,obfsproxy=$OBFSPROXY_TAG,flashproxy=$FLASHPROXY_TAG,libfte=$LIBFTE_TAG,fteproxy=$FTEPROXY_TAG,txsocksx=$TXSOCKSX_TAG $DESCRIPTOR_DIR/mac/gitian-pluggable-transports.yml
  if [ $? -ne 0 ];
  then
    #mv var/build.log ./firefox-fail-mac.log.`date +%Y%m%d%H%M%S`
    exit 1
  fi

  cp -a build/out/pluggable-transports-mac*-gbuilt.zip inputs/
  #cp -a result/pluggable-transports-mac-res.yml inputs/
else
  echo
  echo "****** SKIPPING already built Pluggable Transports Component of Mac Bundle (4/5 for Mac) ******"
  echo
fi


if [ ! -f inputs/bundle-mac.gbuilt ];
then
  echo
  echo "****** Starting Bundling+Localization Component of Mac Bundle (5/5 for Mac) ******"
  echo

  cd $WRAPPER_DIR && ./record-inputs.sh $VERSIONS_FILE && cd $GITIAN_DIR

  ./bin/gbuild -j $NUM_PROCS -m $VM_MEMORY --commit libdmg-hfsplus=$LIBDMG_TAG,https-everywhere=$HTTPSE_TAG,torbutton=$TORBUTTON_TAG,tor-launcher=$TORLAUNCHER_TAG $DESCRIPTOR_DIR/mac/gitian-bundle.yml
  if [ $? -ne 0 ];
  then
    #mv var/build.log ./bundle-fail-mac.log.`date +%Y%m%d%H%M%S`
    exit 1
  fi

  mkdir -p $WRAPPER_DIR/$TORBROWSER_VERSION/
  cp -a build/out/* $WRAPPER_DIR/$TORBROWSER_VERSION/ || exit 1
  touch inputs/bundle-mac.gbuilt
else
  echo
  echo "****** SKIPPING already built Bundling+Localization Component of Mac Bundle (5/5 for Mac) ******"
  echo
fi

echo
echo "****** Mac Bundle complete ******"
echo

