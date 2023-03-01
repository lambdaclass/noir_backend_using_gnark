FFI_LIB_PATH=./gnark_backend_ffi

check: clippy test test-go

build-go:
	$ cd ${FFI_LIB_PATH}; \
		go build -buildmode=c-archive -o libgnark_backend.a main.go

test-go: build-go
	$ cd ${FFI_LIB_PATH}; \
		go test

build: build-go
	$ RUSTFLAGS="-L${FFI_LIB_PATH}" cargo build

test: build-go
	$ RUSTFLAGS="-L${FFI_LIB_PATH}" cargo test ${TEST} -- --nocapture

clippy:
	$ cargo clippy --all-targets -- -D warnings

