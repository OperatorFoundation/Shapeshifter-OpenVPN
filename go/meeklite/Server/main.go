package main

import "C"
import (
	"golang.org/x/net/proxy"
	"net"
	"unsafe"

	"github.com/OperatorFoundation/shapeshifter-transports/transports/meeklite"
)

var configs = map[int]meekliteConfig{}
var conns = map[int]net.Conn{}
var listeners = map[int]net.Listener{}
var nextID = 0

type meekliteConfig struct {
	url   string
	front string
	dialer proxy.Dialer
}

//export MeekliteInitializeServer
func MeekliteInitializeServer(url *C.char, front *C.char, dialer *C.char) (listenerKey int) {
	goUrl := C.GoString(url)
	goFront := C.GoString(front)
	goDialer := C.goString(dialer)

	config := meekliteConfig{goUrl, goFront, goDialer}
	configs[nextID] = config

	// This is the return value
	listenerKey = nextID

	nextID += 1
	return
}

//export MeekliteListen
func MeekliteListen(id int, addressString *C.char) {
	goAddressString := C.GoString(addressString)
	config := configs[id]

	transport := meeklite.NewMeekTransportWithFront(config.url, config.front, config.dialer)
	listener := transport.Listen(goAddressString)
	listeners[id] = listener
}

//export MeekliteAccept
func MeekliteAccept(id int) {
	var listener = listeners[id]

	conn, err := listener.Accept()
	if err != nil {
		return
	}

	conns[id] = conn
}

//export MeekliteWrite
func MeekliteWrite(listenerId int, buffer unsafe.Pointer, bufferLength C.int) int {
	var connection = conns[listenerId]
	var bytesBuffer = C.GoBytes(buffer, bufferLength)
	numberOfBytesWritten, err := connection.Write(bytesBuffer)

	if err != nil {
		return -1
	} else {
		return numberOfBytesWritten
	}
}

//export MeekliteRead
func MeekliteRead(listenerId int, buffer unsafe.Pointer, bufferLength C.int) int {

	var connection = conns[listenerId]
	var bytesBuffer = C.GoBytes(buffer, bufferLength)

	numberOfBytesRead, err := connection.Read(bytesBuffer)

	if err != nil {
		return -1
	} else {
		return numberOfBytesRead
	}
}

//export MeekliteCloseConnection
func MeekliteCloseConnection(listenerId int) {

	var connection = conns[listenerId]
	_ = connection.Close()
	delete(conns, listenerId)
}

func main() {}
