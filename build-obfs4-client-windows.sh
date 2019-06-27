#!/usr/bin/env bash
export BASE=github.com/OperatorFoundation
export SSPATH=Shapeshifter-obfs4-OpenVPN-Transport-Plugin
export CPATH=$SSPATH-C
export CGOPATH=$SSPATH-Cgo

pushd .
cd
mkdir go
cd go
go get $BASE/$CGOPATH
cd src/$BASE/$CGOPATH
popd

cp ~/go/src/$BASE/$CGOPATH/$CGOPATH.h transports/obfs4/$CPATH/include/shapeshifter-obfs4-go.h
cp ~/go/src/$BASE/$CGOPATH/$CGOPATH.a transports/obfs4/$CPATH/lib/shapeshifter-obfs4-go.a

cd transports/obfs4/$CPATH
cmake .
make
