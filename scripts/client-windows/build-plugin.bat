SET GOROOT=%CD%\go-build
SET BASE=github.com/OperatorFoundation/Shapeshifter-OpenVPN
SET WINBASE=github.com\OperatorFoundation\Shapeshifter-OpenVPN

mkdir %GOROOT%
cd %GOROOT%
go get %BASE%/go/%1%
popd
pushd %GOROOT%\src\%WINBASE%\go\%1%
go build -buildmode=c-archive
popd

copy %GOROOT%\src\%WINBASE%\%1%\%1%.h plugins\%1%\client-windows\include\shapeshifter-%1%-go.h
copy %GOROOT%\src\%WINBASE%\%1%\%1%.a plugins\%1%\client-windows\lib\shapeshifter-%1%-go.a

# Run cmake .; make -- we use CLion for this, with the MinGW toolchain
# Copy resulting cmake-build-debug-mingw/libshapeshifter-%1%.dll to openvpn-build/