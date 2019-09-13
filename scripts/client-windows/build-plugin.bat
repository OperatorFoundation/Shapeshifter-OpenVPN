<<<<<<< HEAD
SET GOPATH=%CD%\go-build
=======
SET GOROOT=%CD%\go-build
>>>>>>> 7f2c1cd18105b6ea56bbb6420d561514785f52a6
SET BASE=github.com/OperatorFoundation/Shapeshifter-OpenVPN
SET WINBASE=github.com\OperatorFoundation\Shapeshifter-OpenVPN

mkdir %GOPATH%
pushd %GOPATH%
go get -u %BASE%/go/%1
popd
pushd %GOPATH%\src\%WINBASE%\go\%1
go build -o %1.lib -buildmode=c-archive
popd

copy "%GOPATH%\src\%WINBASE%\go\%1\%1.h" "plugins\%1\client-windows\include\shapeshifter-%1-go.h"
copy "%GOPATH%\src\%WINBASE%\go\%1\%1.lib" "plugins\%1\client-windows\lib\shapeshifter-%1-go.lib"

cd "plugins\%1\client-windows"

REM Run cmake .; make -- we use CLion for this, with the MinGW toolchain
REM Copy resulting cmake-build-debug-mingw/libshapeshifter-%1.dll to openvpn-build/