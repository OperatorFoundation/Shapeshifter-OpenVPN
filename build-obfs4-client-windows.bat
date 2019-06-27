SET BASE=github.com/OperatorFoundation
SET WINBASE=github.com\OperatorFoundation
SET SSPATH=Shapeshifter-obfs4-OpenVPN-Transport-Plugin
SET NEWSSPATH=shapeshifter-obfs4
SET CPATH=%NEWSSPATH%-C
SET CGOPATH=%SSPATH%-Cgo
SET GOPATH=%CD%/go

mkdir go
cd go
go get %BASE%/%CGOPATH%
cd src\%BASE%\%CGOPATH%
go build -buildmode=c-archive
cd ..\..\..\..\..

mkdir transports\obfs4\%CPATH%\include
mkdir transports\obfs4\%CPATH%\lib
copy go\src\%WINBASE%\%CGOPATH%\%CGOPATH%.h transports\obfs4\%CPATH%\include\shapeshifter-obfs4-go.h
copy go\src\%WINBASE%\%CGOPATH%\%CGOPATH%.a transports\obfs4\%CPATH%\lib\shapeshifter-obfs4-go.a

# Run cmake .; make -- we use CLion for this, with the MinGW toolchain
# Copy resulting cmake-build-debug-mingw/libshapeshifter-obfs4.dll to openvpn-build/