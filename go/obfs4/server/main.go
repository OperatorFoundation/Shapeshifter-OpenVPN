package main

import "C"
import (
	"net"
	"unsafe"

	"github.com/OperatorFoundation/shapeshifter-transports/transports/obfs4"
)

var configs = map[int]obfs4ServerConfig{}
var listeners = map[int]net.Listener{}
var conns = map[int]net.Conn{}
var nextID = 0

type obfs4ServerConfig struct{
	stateDir  string
}

//export Obfs4InitializeServer
func Obfs4InitializeServer(stateDir *C.char) (listenerKey int) {
	goStateString := C.GoString(stateDir)
	config := obfs4ServerConfig{goStateString}
	configs[nextID] = config

	// This is the return value
	listenerKey = nextID

	nextID += 1
	return
}

//export Obfs4Listen
func Obfs4Listen(id int, addressString *C.char) {
	goAddressString := C.GoString(addressString)
	config := configs[id]

	transport, _ := obfs4.NewObfs4Server(config.stateDir)
	listener := transport.Listen(goAddressString)
	listeners[id] = listener
}

//export Obfs4Accept
func Obfs4Accept(id int) {
	var listener = listeners[id]

	conn, err := listener.Accept()
	if err != nil {
		return
	}

	conns[id] = conn
}

//export Obfs4Write
func Obfs4Write(listenerId int, buffer unsafe.Pointer, bufferLength C.int) int {
	var connection = conns[listenerId]
	var bytesBuffer = C.GoBytes(buffer, bufferLength)
	numberOfBytesWritten, err := connection.Write(bytesBuffer)

	if err != nil {
		return -1
	} else {
		return numberOfBytesWritten
	}
}

//export Obfs4Read
func Obfs4Read(listenerId int, buffer unsafe.Pointer, bufferLength C.int) int {

	var connection = conns[listenerId]
	var bytesBuffer = C.GoBytes(buffer, bufferLength)

	numberOfBytesRead, err := connection.Read(bytesBuffer)

	if err != nil {
		return -1
	} else {
		return numberOfBytesRead
	}
}

//export Obfs4CloseConnection
func Obfs4CloseConnection(listenerId int) {

	var connection = conns[listenerId]
	_ = connection.Close()
	delete(conns, listenerId)
}

func main() {}
