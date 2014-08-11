#!/bin/bash
#
# fetch-inputs.sh - Fetch our inputs from the source mirror
#

MIRROR_URL=https://people.torproject.org/~mikeperry/mirrors/sources/
MIRROR_URL_DCF=https://people.torproject.org/~dcf/mirrors/sources/
MIRROR_URL_ASN=https://people.torproject.org/~asn/mirrors/sources/
set -e
set -u
umask 0022

if ! [ -e ./versions ]; then
  echo >&2 "Error: ./versions file does not exist"
  exit 1
fi

WRAPPER_DIR=$(dirname "$0")
WRAPPER_DIR=$(readlink -f "$WRAPPER_DIR")

if [ "$#" = 1 ]; then
  INPUTS_DIR="$1"
  VERSIONS_FILE=./versions
elif [ "$#" = 2 ]; then
  INPUTS_DIR="$1"
  VERSIONS_FILE=$2
else
  echo >&2 "Usage: $0 [<inputsdir> <versions>]"
  exit 1
fi

if ! [ -e $VERSIONS_FILE ]; then
  echo >&2 "Error: $VERSIONS_FILE file does not exist"
  exit 1
fi

. $VERSIONS_FILE

mkdir -p "$INPUTS_DIR"
cd "$INPUTS_DIR"


##############################################################################
CLEANUP=$(tempfile)
trap "bash '$CLEANUP'; rm -f '$CLEANUP'" EXIT

# FIXME: This code is copied to verify-tags.sh.. Should we make a bash
# function library?
verify() {
  local file="$1"; shift
  local keyring="$1"; shift
  local suffix="$1"; shift

  local f
  for f in "$file" "$file.$suffix" "$keyring"; do
    if ! [ -e "$f" ]; then
      echo >&2 "Error: Required file $f does not exist."; exit 1
    fi
  done

  local tmpfile=$(tempfile)
  echo "rm -f '$tmpfile'" >> "$CLEANUP"
  local gpghome=$(mktemp -d)
  echo "rm -rf '$gpghome'" >> "$CLEANUP"
  exec 3> "$tmpfile"

  GNUPGHOME="$gpghome" gpg --no-options --no-default-keyring --trust-model=always --keyring="$keyring" --status-fd=3 --verify "$file.$suffix" "$file" >/dev/null 2>&1
  if grep -q '^\[GNUPG:\] GOODSIG ' "$tmpfile"; then
    return 0
  else
    return 1
  fi
}

get() {
  local file="$1"; shift
  local url="$1"; shift

  if ! wget -U "" -N "$url"; then
    echo >&2 "Error: Cannot download $url"
    mv "${file}" "${file}.DLFAILED"
    exit 1
  fi
}

update_git() {
  local dir="$1"; shift
  local url="$1"; shift
  local tag="${1:-}"

  if [ -d "$dir/.git" ];
  then
    (cd "$dir" && git remote set-url origin $url && git fetch --prune origin && git fetch --prune --tags origin)
  else
    if ! git clone "$url"; then
      echo >&2 "Error: Cloning $url failed"
      exit 1
    fi
  fi

  if [ -n "$tag" ]; then
    (cd "$dir" && git checkout "$tag")
  fi

  # If we're not verifying tags, then some of the tags
  # may actually be branch names that require an update
  if [ $VERIFY_TAGS -eq 0 -a -n "$tag" ];
  then
    (cd "$dir" && git pull || true )
  fi
}

checkout_mingw() {
  svn co -r $MINGW_REV https://svn.code.sf.net/p/mingw-w64/code/trunk/ mingw-w64-svn || exit 1
  # XXX: Path
  ZIPOPTS="-x*/.svn/*" faketime -f "2000-01-01 00:00:00" "$WRAPPER_DIR/build-helpers/dzip.sh" mingw-w64-svn-snapshot.zip mingw-w64-svn
}

##############################################################################
# Get package files from mirror

# Get+verify sigs that exist
for i in OPENSSL # OBFSPROXY
do
  PACKAGE="${i}_PACKAGE"
  URL="${MIRROR_URL}${!PACKAGE}"
  SUFFIX="asc"
  get "${!PACKAGE}" "$URL"
  get "${!PACKAGE}.$SUFFIX" "$URL.$SUFFIX"

  if ! verify "${!PACKAGE}" "$WRAPPER_DIR/gpg/$i.gpg" $SUFFIX; then
    echo "$i: GPG signature is broken for ${URL}"
    mv "${!PACKAGE}" "${!PACKAGE}.badgpg"
    exit 1
  fi
done

for i in BINUTILS GCC PYTHON PYCRYPTO M2CRYPTO PYTHON_MSI GMP LXML
do
  PACKAGE="${i}_PACKAGE"
  URL="${i}_URL"
  if [ "${i}" == "PYTHON" -o "${i}" == "PYCRYPTO" -o "${i}" == "M2CRYPTO" -o \
       "${i}" == "PYTHON_MSI" -o "${i}" == "LXML" ]; then
    SUFFIX="asc"
  else
    SUFFIX="sig"
  fi
  get "${!PACKAGE}" "${!URL}"
  get "${!PACKAGE}.$SUFFIX" "${!URL}.$SUFFIX"

  if ! verify "${!PACKAGE}" "$WRAPPER_DIR/gpg/$i.gpg" $SUFFIX; then
    echo "$i: GPG signature is broken for ${!URL}"
    mv "${!PACKAGE}" "${!PACKAGE}.badgpg"
    exit 1
  fi
done

for i in TOOLCHAIN4 TOOLCHAIN4_OLD OSXSDK MSVCR100
do
  PACKAGE="${i}_PACKAGE"
  URL="${MIRROR_URL}${!PACKAGE}"
  get "${!PACKAGE}" "${MIRROR_URL}${!PACKAGE}"
done

# XXX: Omit ARGPARSE because Google won't allow wget -N and because the
# download seems to 404 about 50% of the time.
for i in ARGPARSE
do
  PACKAGE="${i}_PACKAGE"
  URL="${MIRROR_URL_DCF}${!PACKAGE}"
  get "${!PACKAGE}" "${MIRROR_URL_DCF}${!PACKAGE}"
done

for i in PYYAML
do
  PACKAGE="${i}_PACKAGE"
  URL="${MIRROR_URL_ASN}${!PACKAGE}"
  get "${!PACKAGE}" "${MIRROR_URL_ASN}${!PACKAGE}"
done

for i in ZOPEINTERFACE TWISTED PY2EXE SETUPTOOLS PARSLEY SRIBUNDLE
do
  URL="${i}_URL"
  PACKAGE="${i}_PACKAGE"
  get "${!PACKAGE}" "${!URL}"
done

# Verify packages with weak or no signatures via multipath downloads
# (OpenSSL is signed with MD5, and OSXSDK is not signed at all)
# XXX: Google won't allow wget -N.. We need to re-download the whole
# TOOLCHAIN4 each time. Rely only on SHA256 for now..
mkdir -p verify
cd verify
for i in OPENSSL OSXSDK
do
  URL="${i}_URL"
  PACKAGE="${i}_PACKAGE"
  if ! wget -U "" -N --no-remove-listing "${!URL}"; then
    echo "$i url ${!URL} is broken!"
    mv "${!PACKAGE}" "${!PACKAGE}.removed"
    exit 1
  fi
  if ! diff "${!PACKAGE}" "../${!PACKAGE}"; then
    echo "Package ${!PACKAGE} differs from our mirror's version!"
    exit 1
  fi
done

cd ..

# NoScript and HTTPS-Everywhere are magikal and special:
wget -U "" -N ${NOSCRIPT_URL}
wget -U "" -N ${HTTPSE_URL}

# So is mingw:
if [ ! -f mingw-w64-svn-snapshot.zip ];
then
  checkout_mingw
else
  # We do have mingw-w64 already but is it the correct revision? We check the
  # hash of the zip archive as it has to be changed as well if a new revision
  # should be used.
   if ! echo "${MINGW_HASH}  ${MINGW_PACKAGE}" | sha256sum -c -; then
     # We need to update the local mingw-w64 copy
     rm -rf mingw-w64-svn*
     checkout_mingw
   fi
fi

# Verify packages with weak or no signatures via direct sha256 check
# (OpenSSL is signed with MD5, and OSXSDK is not signed at all)
for i in OSXSDK TOOLCHAIN4 TOOLCHAIN4_OLD NOSCRIPT HTTPSE MINGW MSVCR100 PYCRYPTO ARGPARSE PYYAML ZOPEINTERFACE TWISTED M2CRYPTO SETUPTOOLS OPENSSL GMP PARSLEY
do
   PACKAGE="${i}_PACKAGE"
   HASH="${i}_HASH"
   if ! echo "${!HASH}  ${!PACKAGE}" | sha256sum -c -; then
     echo "Package hash for ${!PACKAGE} differs from our locally stored sha256!"
     exit 1
   fi
done

mkdir -p langpacks-$FIREFOX_LANG_VER/linux-langpacks
mkdir -p langpacks-$FIREFOX_LANG_VER/win32-langpacks
mkdir -p langpacks-$FIREFOX_LANG_VER/mac-langpacks

cd langpacks-$FIREFOX_LANG_VER

for i in $BUNDLE_LOCALES
do
  cd linux-langpacks
  wget -U "" -N "https://ftp.mozilla.org/pub/mozilla.org/firefox/releases/$FIREFOX_LANG_VER/linux-i686/xpi/$i.xpi"
  cd ..
  cd win32-langpacks
  wget -U "" -N "https://ftp.mozilla.org/pub/mozilla.org/firefox/releases/$FIREFOX_LANG_VER/win32/xpi/$i.xpi"
  cd ..
  cd mac-langpacks
  wget -U "" -N "https://ftp.mozilla.org/pub/mozilla.org/firefox/releases/$FIREFOX_LANG_VER/mac/xpi/$i.xpi"
  cd ..
done

"$WRAPPER_DIR/build-helpers/dzip.sh" ../win32-langpacks.zip win32-langpacks
"$WRAPPER_DIR/build-helpers/dzip.sh" ../linux-langpacks.zip linux-langpacks
"$WRAPPER_DIR/build-helpers/dzip.sh" ../mac-langpacks.zip mac-langpacks

cd ..

ln -sf "$NOSCRIPT_PACKAGE" noscript@noscript.net.xpi
ln -sf "$HTTPSE_PACKAGE" https-everywhere@eff.org.xpi
ln -sf "$OPENSSL_PACKAGE" openssl.tar.gz
ln -sf "$BINUTILS_PACKAGE" binutils.tar.bz2
ln -sf "$GCC_PACKAGE" gcc.tar.bz2
ln -sf "$PYTHON_PACKAGE" python.tar.bz2
ln -sf "$PYTHON_MSI_PACKAGE" python.msi
ln -sf "$PYCRYPTO_PACKAGE" pycrypto.tar.gz
ln -sf "$ARGPARSE_PACKAGE" argparse.tar.gz
ln -sf "$PYYAML_PACKAGE" pyyaml.tar.gz
ln -sf "$ZOPEINTERFACE_PACKAGE" zope.interface.zip
ln -sf "$TWISTED_PACKAGE" twisted.tar.bz2
ln -sf "$M2CRYPTO_PACKAGE" m2crypto.tar.gz
ln -sf "$PY2EXE_PACKAGE" py2exe.exe
ln -sf "$SETUPTOOLS_PACKAGE" setuptools.tar.gz
ln -sf "$GMP_PACKAGE" gmp.tar.bz2
ln -sf "$LXML_PACKAGE" lxml.tar.gz
ln -sf "$PARSLEY_PACKAGE" parsley.tar.gz

# Fetch latest gitian-builder itself
# XXX - this is broken if a non-standard inputs dir is selected using the command line flag.
cd ..
git remote set-url origin https://git.torproject.org/builders/gitian-builder.git
git fetch origin
git fetch --tags origin # XXX - why do we fetch tags specifically?
git checkout tor-browser-builder-3
git merge origin/tor-browser-builder-3
cd inputs

while read dir url tag; do
  echo "updating ${dir} ${url} ${tag}"  
  update_git "$dir" "$url" "$tag"
done << EOF
tbb-windows-installer https://github.com/MarkCSmith/tbb-windows-installer.git $NSIS_TAG
zlib                  https://github.com/madler/zlib.git       $ZLIB_TAG
libevent              https://github.com/libevent/libevent.git $LIBEVENT_TAG
tor                   https://git.torproject.org/tor.git              $TOR_TAG
https-everywhere      https://git.torproject.org/https-everywhere.git $HTTPSE_TAG
torbutton             https://git.torproject.org/torbutton.git            $TORBUTTON_TAG
tor-launcher          https://git.torproject.org/tor-launcher.git         $TORLAUNCHER_TAG
tor-browser           https://git.torproject.org/tor-browser.git          $TORBROWSER_TAG
pyptlib               https://git.torproject.org/pluggable-transports/pyptlib.git $PYPTLIB_TAG
obfsproxy https://git.torproject.org/pluggable-transports/obfsproxy.git $OBFSPROXY_TAG
flashproxy            https://git.torproject.org/flashproxy.git $FLASHPROXY_TAG
libfte                https://github.com/kpdyer/libfte.git $LIBFTE_TAG
fteproxy              https://github.com/kpdyer/fteproxy.git $FTEPROXY_TAG
libdmg-hfsplus        https://github.com/vasi/libdmg-hfsplus.git $LIBDMG_TAG
txsocksx              https://github.com/habnabit/txsocksx.git $TXSOCKSX_TAG
jel                   https://github.com/SRI-CSL/jel.git $JEL_TAG
stegotorus            https://github.com/SRI-CSL/stegotorus.git $STEGOTORUS_TAG
jansson               https://github.com/akheron/jansson.git $JANSSON_TAG
zlib                  https://github.com/madler/zlib.git $ZLIB_TAG
EOF

exit 0

