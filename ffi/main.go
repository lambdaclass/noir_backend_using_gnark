package main

import "C"

//export Ping
func Ping(msg string) *C.char {
    if msg != "ping" {
   		return C.CString("...")
    }
    return C.CString("pong")
}

func main() {}