#!/usr/bin/env bash
export BASE=github.com/OperatorFoundation
export SSPATH=Shapeshifter-obfs4-OpenVPN-Transport-Plugin-server
export CPATH=shapeshifter-obfs4-server-1.0
export CGOPATH=$SSPATH-Cgo

pushd .
cd
mkdir -p go
cd go
go get $BASE/$CGOPATH
cd src/$BASE/$CGOPATH
./build.sh
popd

cp ~/go/src/$BASE/$CGOPATH/$CGOPATH.h transports/obfs4/$CPATH/include/shapeshifter-obfs4-server-go.h
cp ~/go/src/$BASE/$CGOPATH/$CGOPATH.a transports/obfs4/$CPATH/lib/shapeshifter-obfs4-server-go.a

cd transports/obfs4/$CPATH
cmake .
make

cpack -v -G DEB
