package main

import "C"
import (
	"net"
	"unsafe"

	"github.com/OperatorFoundation/shapeshifter-transports/transports/shadow"
)

var configs = map[int]shadowConfig{}
var listeners = map[int]net.Listener{}
var conns = map[int]net.Conn{}
var nextID = 0

type shadowConfig struct {
	password   string
	cipherName string
}

//export ShadowInitializeServer
func ShadowInitializeServer(password *C.char, cipherName *C.char) (listenerKey int) {
	goPassword := C.GoString(password)
	goCipherName := C.GoString(cipherName)

	config := shadowConfig{goPassword, goCipherName}
	configs[nextID] = config

	// This is the return value
	listenerKey = nextID

	nextID += 1
	return
}

//export ShadowListen
func ShadowListen(id int, addressString *C.char) {
	goAddressString := C.GoString(addressString)
	config := configs[id]

	transport := shadow.NewShadowServer(config.password, config.cipherName)
	listener := transport.Listen(goAddressString)
	listeners[id] = listener
}

//export ShadowAccept
func ShadowAccept(id int) {
	var listener = listeners[id]

	conn, err := listener.Accept()
	if err != nil {
		return
	}

	conns[id] = conn
}

//export ShadowWrite
func ShadowWrite(listenerId int, buffer unsafe.Pointer, bufferLength C.int) int {
	var connection = conns[listenerId]
	var bytesBuffer = C.GoBytes(buffer, bufferLength)
	numberOfBytesWritten, err := connection.Write(bytesBuffer)

	if err != nil {
		return -1
	} else {
		return numberOfBytesWritten
	}
}

//export ShadowRead
func ShadowRead(listenerId int, buffer unsafe.Pointer, bufferLength C.int) int {

	var connection = conns[listenerId]
	var bytesBuffer = C.GoBytes(buffer, bufferLength)

	numberOfBytesRead, err := connection.Read(bytesBuffer)

	if err != nil {
		return -1
	} else {
		return numberOfBytesRead
	}
}

//export ShadowCloseConnection
func ShadowCloseConnection(listenerId int) {

	var connection = conns[listenerId]
	_ = connection.Close()
	delete(conns, listenerId)
}

func main() {}
