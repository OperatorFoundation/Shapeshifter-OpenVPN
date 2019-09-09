package main

import "C"
import (
	"net"
	"unsafe"

	obfs4transport "github.com/OperatorFoundation/shapeshifter-transports/transports/obfs4"
)

var transports = map[int]obfs4transport.Obfs4Transport{}
var listeners = map[int]net.Listener{}
var conns = map[int]net.Conn{}
var nextID = 0

//export Obfs4InitializeServer
func Obfs4InitializeServer(stateDir *C.char) (listenerKey int) {
	goStateString := C.GoString(stateDir)
	transports[nextID] = obfs4transport.NewObfs4Server(goStateString)

	// This is the return value
	listenerKey = nextID

	nextID += 1
	return
}

//export Obfs4Listen
func Obfs4Listen(id int, addressString *C.char) {
	goAddressString := C.GoString(addressString)

	transport := transports[id]
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
