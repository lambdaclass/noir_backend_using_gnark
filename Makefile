FFI_LIB_PATH=./gnark_backend_ffi

build-go:
	$ cd ${FFI_LIB_PATH}; \
		go build -buildmode=c-archive -o libgnark_backend.a main.go

build: build-go
	$ RUSTFLAGS="-L${FFI_LIB_PATH}" cargo build

test: build-go
	$ RUSTFLAGS="-L${FFI_LIB_PATH}" cargo test

clippy:
	$ cargo clippy --all-targets -- -D warnings

check: clippy test
