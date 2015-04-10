#!/bin/bash -xe
VERSION=5.3.0

if [ "x$PKGFORMAT" == "xdeb" ]
then
    # debian denotes 64 arches with amd64
    [ "x$ARCH" == "xx86_64" ] && ARCH="amd64" || true
    [ -d agent-deb ] || git clone git@github.com:Stackdriver/agent-deb.git
    pushd agent-deb
    git pull
    make clean
    make DISTRO="$DISTRO" ARCH="$ARCH" VERSION="$VERSION" BUILD_NUM="$BUILD_NUM" build
    if [ $? -ne 0 ]
    then
        exit $?
    fi
	popd
	[ -d result ] && rm -rf result || true
	cp -r agent-deb/result .
elif [ "x$PKGFORMAT" == "xrpm" ]
then
    [ -d agent-rpm ] || git clone git@github.com:Stackdriver/agent-rpm.git
    pushd agent-rpm
    git pull
    make clean
    make DISTRO="$DISTRO" ARCH="$ARCH" VERSION="$VERSION" BUILD_NUM="$BUILD_NUM" build
    if [ $? -ne 0 ]
    then
        exit $?
    fi
    popd
    [ -d result ] && rm -rf result || true
	cp -r agent-rpm/result .
else
    echo "I don't know how to handle label '$PKGFORMAT'. Aborting build"
    exit 1
fi

