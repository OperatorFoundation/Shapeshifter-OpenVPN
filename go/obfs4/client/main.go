package main
import "C"
import (
	"github.com/OperatorFoundation/shapeshifter-transports/transports/obfs4"
	"net"
	"unsafe"
)

var obfs4Clients = map[int]*obfs4.Obfs4Transport{}
var obfs4Connections = map[int]net.Conn{}
var nextID = 0

//export InitializeObfs4CClient
func InitializeObfs4CClient(certString *C.char, iatMode int) (clientKey int) {

	goCertString := C.GoString(certString)
	var obfs4Client *obfs4.Obfs4Transport = obfs4.NewObfs4Client(goCertString, iatMode)
	obfs4Clients[nextID] = obfs4Client

	// This is the return value
	clientKey = nextID

	nextID += 1
	return
}

//export Obfs4Dial
func Obfs4Dial(clientId int, addressString *C.char) int {

	goAddressString := C.GoString(addressString)

	transport := obfs4Clients[clientId]
	obfs4TransportConnection, err := transport.Dial(goAddressString)

	if err != nil {
		return 1
	} else {
		obfs4Connections[clientId] = obfs4TransportConnection
		return 0
	}
}

//export Obfs4Write
func Obfs4Write(clientId int, buffer unsafe.Pointer, bufferLength C.int) int {
	var connection = obfs4Connections[clientId]
	var bytesBuffer = C.GoBytes(buffer, bufferLength)
	numberOfBytesWritten, err := connection.Write(bytesBuffer)

	if err != nil {
		return -1
	} else {
		return numberOfBytesWritten
	}
}

//export Obfs4Read
func Obfs4Read(clientId int, buffer unsafe.Pointer, bufferLength C.int) int {

	var connection = obfs4Connections[clientId]
	var bytesBuffer = C.GoBytes(buffer, bufferLength)

	numberOfBytesRead, err := connection.Read(bytesBuffer)

	if err != nil {
		return -1
	} else {
		return numberOfBytesRead
	}
}

//export Obfs4CloseConnection
func Obfs4CloseConnection(clientId int) {

	var connection = obfs4Connections[clientId]
	_ = connection.Close()
	delete(obfs4Connections, clientId)
	delete(obfs4Clients, clientId)
}

func main() {}