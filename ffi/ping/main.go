package main

import "C"
import "unsafe"

//export Ping
func Ping(msg string) unsafe.Pointer {
	if msg != "ping" {
		return C.CBytes([]byte(msg))
	}
	return C.CBytes([]byte("pong"))
}

func main() {}
