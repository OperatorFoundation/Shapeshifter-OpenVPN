#!/usr/bin/env bash
export GOPATH="$PWD/go-build"
export BASE=github.com/OperatorFoundation/Shapeshifter-OpenVPN/go

mkdir -p "$GOPATH"
pushd "$GOPATH" || exit
go get -u "$BASE/$1/server"
popd || exit
pushd "$GOPATH/src/$BASE/$1/server" || exit
go build -o "$1.a" -buildmode=c-archive
popd || exit

cp "$GOPATH/src/$BASE/$1/server/$1.h" "plugins/$1/server-linux/shapeshifter-$1-server-1.0/include/shapeshifter-$1-go.h"
cp "$GOPATH/src/$BASE/$1/server/$1.a" "plugins/$1/server-linux/shapeshifter-$1-server-1.0/lib/shapeshifter-$1-go.a"

cd "plugins/$1/server-linux/shapeshifter-$1-server-1.0" || exit
cmake .
make

cpack -v -G DEB
