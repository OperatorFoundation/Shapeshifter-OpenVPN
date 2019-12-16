package main

import "C"
import (
	"net"
	"unsafe"

	"github.com/OperatorFoundation/shapeshifter-transports/transports/meekserver"
)

var configs = map[int]meekserverConfig{}
var listeners = map[int]net.Listener{}
var conns = map[int]net.Conn{}
var nextID = 0

type meekserverConfig struct {
	disableTLS          bool
	acmeEmail           string
	acmeHostnamesCommas string
	stateDir            string
}

//export meekserverInitializeServer
func meekserverInitializeServer(disableTLS *C.char, acmeEmail *C.char, acmeHostnamesCommas *C.char, stateDir *C.char) (listenerKey int) {
	goDisableTLS := C.GoString(disableTLS)
	goAcmeEmail := C.GoString(acmeEmail)
	goAcmeHostnamesCommas := C.GoString(acmeHostnamesCommas)
	goStateDir := C.GoString(stateDir)

	config := meekserverConfig{goDisableTLS, goAcmeEmail, goAcmeHostnamesCommas, goStateDir}
	configs[nextID] = config

	// This is the return value
	listenerKey = nextID

	nextID += 1
	return
}

//export meekserverListen
func meekserverListen(id int, addressString *C.char) {
	goAddressString := C.GoString(addressString)
	config := configs[id]

	transport := meekserver.NewMeekTransportServer(config.disableTLS, config.acmeEmail, config.acmeHostnamesCommas, config.stateDir)
	listener := transport.Listen(goAddressString)
	listeners[id] = listener
}

//export meekserverAccept
func meekserverAccept(id int) {
	var listener = listeners[id]

	conn, err := listener.Accept()
	if err != nil {
		return
	}

	conns[id] = conn
}

//export meekserverWrite
func meekserverWrite(listenerId int, buffer unsafe.Pointer, bufferLength C.int) int {
	var connection = conns[listenerId]
	var bytesBuffer = C.GoBytes(buffer, bufferLength)
	numberOfBytesWritten, err := connection.Write(bytesBuffer)

	if err != nil {
		return -1
	} else {
		return numberOfBytesWritten
	}
}

//export meekserverRead
func meekserverRead(listenerId int, buffer unsafe.Pointer, bufferLength C.int) int {

	var connection = conns[listenerId]
	var bytesBuffer = C.GoBytes(buffer, bufferLength)

	numberOfBytesRead, err := connection.Read(bytesBuffer)

	if err != nil {
		return -1
	} else {
		return numberOfBytesRead
	}
}

//export meekserverCloseConnection
func meekserverCloseConnection(listenerId int) {

	var connection = conns[listenerId]
	_ = connection.Close()
	delete(conns, listenerId)
}

func main() {}
