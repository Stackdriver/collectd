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
	      sys_resource \
	      sys_wait \
	      setlocale \
	      strtok_r \
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
	export CFLAGS="-Drestrict=__restrict -I${GNULIB_DIR}"
	export LDFLAGS="-L${GNULIB_DIR} ${LDFLAGS}"
	export LIBS="-lgnu"
	popd
else
	echo "Building for Linux..."
fi

set -x

autoheader \
&& aclocal -I ${LIBTOOL_DIR}/share/aclocal \
&& $libtoolize --ltdl --copy --force \
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
	  --prefix="${INSTALL_DIR}" \
	  --libdir="${LIBDIR}" \
	  --bindir="${BINDIR}" \
	  --sbindir="${SBINDIR}" \
	  --sysconfdir="${SYSCONFDIR}" \
	  --localstatedir="${LOCALSTATEDIR}" \
	  --datarootdir="${DATAROOTDIR}" \
	  --datarootdir="${DATADIR}" \
	  --disable-all-plugins \
	  --host="$HOST" \
	  --with-fp-layout="nothing" \
	  --enable-logfile \
	  --enable-disk \
	  --enable-eventlog \
	  --enable-interface \
	  --enable-match_regex \
	  --enable-network \
	  --enable-target_replace \
	  --enable-target_set \
	  --enable-wmi

	# TODO: find a sane way to set LTCFLAGS for libtool
	cp libtool libtool_bak
	sed -i "s%\$LTCC \$LTCFLAGS\(.*cwrapper.*\)%\$LTCC \1%" libtool

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

