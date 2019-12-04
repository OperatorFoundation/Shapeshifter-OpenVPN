package main

import "C"
import (
	"golang.org/x/net/proxy"
	"net"
	"unsafe"

	"github.com/OperatorFoundation/shapeshifter-transports/transports/meeklite"
)

var configs = map[int]meekConfig{}
var conns = map[int]net.Conn{}
var nextID = 0

type meekConfig struct {
	url   string
	front string
}

//export MeekliteInitializeClient
func MeekliteInitializeClient(url *C.char, front *C.char) (listenerKey int) {
	goUrl := C.GoString(url)
	goFront := C.GoString(front)

	config := meekConfig{goUrl, goFront}
	configs[nextID] = config
	// This is the return value
	listenerKey = nextID

	nextID += 1
	return
}

//export MeekliteDial
func MeekliteDial(id int, addressString *C.char) int {
	goAddressString := C.GoString(addressString)
	config := configs[id]

	transport := meeklite.NewMeekTransportWithFront(config.url, config.front, proxy.Direct)
	conn := transport.Dial(goAddressString)

	if conn == nil {
		return 1
	} else {
		conns[id] = conn
		return 0
	}
}

//export MeekliteWrite
func MeekliteWrite(clientId int, buffer unsafe.Pointer, bufferLength C.int) int {
	var connection = conns[clientId]
	var bytesBuffer = C.GoBytes(buffer, bufferLength)
	numberOfBytesWritten, err := connection.Write(bytesBuffer)

	if err != nil {
		return -1
	} else {
		return numberOfBytesWritten
	}
}

//export MeekliteRead
func MeekliteRead(clientId int, buffer unsafe.Pointer, bufferLength C.int) int {

	var connection = conns[clientId]
	var bytesBuffer = C.GoBytes(buffer, bufferLength)

	numberOfBytesRead, err := connection.Read(bytesBuffer)

	if err != nil {
		return -1
	} else {
		return numberOfBytesRead
	}
}

//export MeekliteCloseConnection
func MeekliteCloseConnection(clientId int) {

	var connection = conns[clientId]
	_ = connection.Close()
	delete(conns, clientId)
}

func main() {}
