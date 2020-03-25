#! /bin/bash

GLOBAL_ERROR_INDICATOR=0

if test "${OSTYPE}" = "cygwin"; then
	WINDOWS=yes
fi

check_for_application ()
{
	for PROG in "$@"
	do
		which "$PROG" >/dev/null 2>&1
		if test $? -ne 0; then
			cat >&2 <<EOF
WARNING: \`$PROG' not found!
    Please make sure that \`$PROG' is installed and is in one of the
    directories listed in the PATH environment variable.
EOF
			GLOBAL_ERROR_INDICATOR=1
		fi
	done
}

check_for_application lex yacc autoheader aclocal automake autoconf

# Actually we don't need the pkg-config executable, but we need the M4 macros.
# We check for `pkg-config' here and hope that M4 macros will then be
# available, too.
check_for_application pkg-config

LIBTOOL_DIR=/usr

if test "${WINDOWS}" = "yes"; then
	HOST=x86_64-w64-mingw32
	CC=${HOST}-gcc
	check_for_application git make $CC

	TOP_SRCDIR=$(pwd)
	mkdir -p _build_aux

	# Build libtool
	LIBTOOL_DIR="${TOP_SRCDIR}/_build_aux/_libtool"
	pushd _build_aux
	if [ -d "_libtool" ]; then
		echo "Assuming that libtool is already built, because _libtool exists."
	else
		wget http://ftpmirror.gnu.org/libtool/libtool-2.4.6.tar.gz
		tar xf libtool-2.4.6.tar.gz
		cd libtool-2.4.6
		./configure --host="$HOST" --prefix="${LIBTOOL_DIR}"
		make
		make install
	fi
	PATH="${LIBTOOL_DIR}/bin:${PATH}"
	export LDFLAGS="-L${LIBTOOL_DIR}/bin -L${LIBTOOL_DIR}/lib ${LDFLAGS}"
	popd
fi

libtoolize=""
libtoolize --version >/dev/null 2>/dev/null
if test $? -eq 0
then
	libtoolize=libtoolize
else
	glibtoolize --version >/dev/null 2>/dev/null
	if test $? -eq 0
	then
		libtoolize=glibtoolize
	else
		cat >&2 <<EOF
WARNING: Neither \`libtoolize' nor \`glibtoolize' have been found!
    Please make sure that one of them is installed and is in one of the
    directories listed in the PATH environment variable.
EOF
		GLOBAL_ERROR_INDICATOR=1
	fi
 fi

if test "$GLOBAL_ERROR_INDICATOR" != "0"
then
	exit 1
fi

if test "${WINDOWS}" = "yes"; then
	echo "Building for Windows..."

	set -e

	# Build libcurl
	pushd _build_aux
	LIBCURL_DIR="${TOP_SRCDIR}/_build_aux/_libcurl"
	if [ -d "_libcurl" ]; then
	  echo "Assuming that libcurl is already built, because _libcurl exists."
	else
	  wget http://curl.haxx.se/download/curl-7.44.0.tar.gz
	  tar xf curl-7.44.0.tar.gz
	  cd curl-7.44.0
	  ./configure --host="$HOST" --with-winssl --prefix="${LIBCURL_DIR}"
	  make
	  make install
	fi
	popd

	# Install libyajl
	pushd _build_aux
	LIBYAJL_DIR="${TOP_SRCDIR}/_build_aux/_libyajl"
	if [ -d "_libyajl" ]; then
	  echo "Assuming that libyajl is already built, because _libyajl exists."
	else
	  wget http://repo.msys2.org/mingw/x86_64/mingw-w64-x86_64-yajl-2.1.0-1-any.pkg.tar.xz
	  mkdir _libyajl
	  tar xf mingw-w64-x86_64-yajl-2.1.0-1-any.pkg.tar.xz --strip-components=1 -C _libyajl
	fi
	popd

	# Install openssl
	pushd _build_aux
	OPENSSL_DIR="${TOP_SRCDIR}/_build_aux/_openssl"
	if [ -d "_openssl" ]; then
	  echo "Assuming that openssl is already built, because _openssl exists."
	else
	  wget http://repo.msys2.org/mingw/x86_64/mingw-w64-x86_64-openssl-1.0.2.p-1-any.pkg.tar.xz
	  mkdir _openssl
	  tar xf mingw-w64-x86_64-openssl-1.0.2.p-1-any.pkg.tar.xz --strip-components=1 -C _openssl
	fi
	popd

	# Install OpenJDK 11
	pushd _build_aux
	JAVA_DIR="${TOP_SRCDIR}/_build_aux/_openjdk11"
	if [ -d "_openjdk11" ]; then
	  echo "Assuming that openssl is already built, because _openjdk11 exists."
	else
	  wget https://download.java.net/openjdk/jdk11/ri/openjdk-11+28_windows-x64_bin.zip
	  unzip openjdk-11+28_windows-x64_bin.zip && mv jdk-11 _openjdk11
	  cd _openjdk11/lib
	  gendef ../bin/server/jvm.dll
	  x86_64-w64-mingw32-dlltool --as-flags=--64 -m i386:x86-64 -k --output-lib libjvm.a --input-def jvm.def
	fi
	export JAVAC=/usr/bin/javac  # Need to use the system javac.
	export JAR=/usr/bin/jar  # Need to use the system jar.
	export JAVA_LDFLAGS="-L${JAVA_DIR}/lib ${JAVA_LDFLAGS}"
	popd

	# Build gnulib
	pushd _build_aux
	GNULIB_DIR="${TOP_SRCDIR}/_build_aux/_gnulib/gllib"
	if [ -d "_gnulib" ]; then
	  echo "Assuming that gnulib is already built, because _gnulib exists."
	else
	  git clone git://git.savannah.gnu.org/gnulib.git
	  cd gnulib
	  git checkout 2f8140bc8ce5501e31dcc665b42b5df64f84c20c
	  ./gnulib-tool --create-testdir \
	      --source-base=lib \
	      --dir=${TOP_SRCDIR}/_build_aux/_gnulib \
	      canonicalize-lgpl \
	      regex \
	      sys_socket \
	      nanosleep \
	      netdb \
	      net_if \
	      sendto \
	      gettimeofday \
	      getsockopt \
	      time_r \
	      sys_stat \
	      fcntl-h \
	      flock \
	      sys_resource \
	      sys_wait \
	      setlocale \
	      strtok_r \
	      strndup \
	      poll \
	      recv \
	      net_if \
	      fnmatch

	  cd ${TOP_SRCDIR}/_build_aux/_gnulib
	  ./configure --host="$HOST" LIBS="-lws2_32 -lpthread"
	  make 
	  cd gllib

	  # We have to rebuild libgnu.a to get the list of *.o files to build a dll later
	  rm libgnu.a
	  OBJECT_LIST=`make V=1 | grep "ar" | cut -d' ' -f4-`
	  $CC -shared -o libgnu.dll $OBJECT_LIST -lws2_32 -lpthread
	  rm libgnu.a # get rid of it, to use libgnu.dll
	fi
	export CFLAGS="-Drestrict=__restrict -I${GNULIB_DIR} ${CFLAGS}"
	export LDFLAGS="-L${GNULIB_DIR} ${LDFLAGS}"
	export LIBS="-lgnu ${LIBS}"
	popd
else
	echo "Building for Linux..."
fi

set -x

autoheader \
&& $libtoolize --ltdl --copy --force \
&& aclocal -Im4 -I${LIBTOOL_DIR}/share/aclocal \
&& automake --add-missing --copy \
&& autoconf

if test "${WINDOWS}" = "yes"; then
	MINGW_ROOT="/usr/x86_64-w64-mingw32/sys-root/mingw"

	: ${INSTALL_DIR:="C:/PROGRA~1/collectd"}
	: ${LIBDIR:="${INSTALL_DIR}"}
	: ${BINDIR:="${INSTALL_DIR}"}
	: ${SBINDIR:="${INSTALL_DIR}"}
	: ${SYSCONFDIR:="${INSTALL_DIR}"}
	: ${LOCALSTATEDIR:="${INSTALL_DIR}"}
	: ${DATAROOTDIR:="${INSTALL_DIR}"}
	: ${DATADIR:="${INSTALL_DIR}"}

	echo "Installing collectd to ${INSTALL_DIR}."

	./configure \
	  --host="$HOST" \
	  --with-fp-layout="nothing" \
	  --prefix="${INSTALL_DIR}" \
	  --libdir="${LIBDIR}" \
	  --bindir="${BINDIR}" \
	  --sbindir="${SBINDIR}" \
	  --sysconfdir="${SYSCONFDIR}" \
	  --localstatedir="${LOCALSTATEDIR}" \
	  --datarootdir="${DATAROOTDIR}" \
	  --datarootdir="${DATADIR}" \
	  --program-prefix=stackdriver- \
	  --disable-all-plugins \
	  --disable-static \
	  --disable-perl --without-libperl  --without-perl-bindings \
	  --with-libcurl="${LIBCURL_DIR}" \
	  --with-libyajl="${LIBYAJL_DIR}" \
	  --with-libssl="${OPENSSL_DIR}" \
	  --enable-disk \
	  --enable-logfile \
	  --enable-eventlog \
	  --enable-interface \
	  IGNORE="--enable-tcpconns" \
	  --enable-write_http \
	  --enable-aggregation \
	  --enable-csv \
	  --enable-nginx \
	  --enable-apache \
	  IGNORE="--enable-memcached" \
	  IGNORE="--enable-mysql" \
	  IGNORE="--enable-protocols" \
	  --enable-plugin_mem \
	  IGNORE="--enable-processes" \
	  IGNORE="--enable-python" \
	  IGNORE="--enable-ntpd" \
	  IGNORE="--enable-nfs" \
	  --enable-stackdriver_agent \
	  IGNORE="--enable-exec" \
	  --enable-tail \
	  IGNORE="--enable-statsd" \
	  --enable-network \
	  --enable-match_regex --enable-target_set \
	  --enable-target_replace --enable-target_scale \
	  --enable-match_throttle_metadata_keys \
	  --enable-write_log \
	  --enable-wmi \
	  --with-useragent="stackdriver_agent/$(debian_version)" \
	  --enable-java --with-java="${JAVA_DIR}" \
	  IGNORE="--enable-redis --with-libhiredis" \
	  --enable-curl \
	  --enable-curl_json \
	  --enable-write_gcm \
	  --enable-debug

	# TODO: find a sane way to set LTCFLAGS for libtool
	cp libtool libtool_bak
	sed -i "s%\$LTCC \$LTCFLAGS\(.*cwrapper.*\)%\$LTCC -include '${GNULIB_DIR}/../config.h' \1%" libtool

	cp ${GNULIB_DIR}/../config.h src/gnulib_config.h
	echo "#include <config.h.in>" >> src/gnulib_config.h

	make

	if test "${NOINSTALL:-no}" != yes; then
		make install

		cp ".libs/libcollectd-0.dll" "${INSTALL_DIR}"
		cp "${GNULIB_DIR}/libgnu.dll" "${INSTALL_DIR}"
		cp "${LIBTOOL_DIR}/bin/libltdl-7.dll" "${INSTALL_DIR}"
		cp "${MINGW_ROOT}/bin/zlib1.dll" "${INSTALL_DIR}"
		cp "${MINGW_ROOT}/bin/libwinpthread-1.dll" "${INSTALL_DIR}"
		cp "${MINGW_ROOT}/bin/libdl.dll" "${INSTALL_DIR}"
	fi

	echo "Done"
fi

