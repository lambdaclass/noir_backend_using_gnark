package structs

import "gnark_backend_ffi/backend"

type DirectiveInvert struct {
	X      backend.Witness
	Result backend.Witness
}
