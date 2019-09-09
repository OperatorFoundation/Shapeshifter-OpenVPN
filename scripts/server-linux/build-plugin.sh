#!/usr/bin/env bash
export GOROOT=$PWD/go-build
export BASE=github.com/OperatorFoundation/Shapeshifter-OpenVPN

mkdir -p $GOROOT
pushd $GOROOT
go get $BASE/$1
popd
pushd $GOROOT/src/$BASE/$1
go build -buildmode=c-archive
popd

cp $GOROOT/src/$BASE/$1/$1.h plugins/$1/server-linux/include/shapeshifter-$1-go.h
cp $GOROOT/src/$BASE/$1/$1.a plugins/$1/server-linux/lib/shapeshifter-$1-go.a

cd plugins/$1/server-linux
cmake .
make

cpack -v -G DEB
