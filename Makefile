FFI_LIB_PATH=./gnark_backend_ffi

check: clippy test test-go

build-go:
	$ cd ${FFI_LIB_PATH}; \
		go build -buildmode=c-archive -o libgnark_backend.a main.go

# Temporary solution for testing the only tests we have. We should test recurively.
test-go: 
	$ cd ${FFI_LIB_PATH}; \
		go test -run '' gnark_backend_ffi/structs

build: build-go
	$ RUSTFLAGS="-L${FFI_LIB_PATH}" cargo build

test: build-go
	$ RUSTFLAGS="-L${FFI_LIB_PATH}" cargo test ${TEST} -- --nocapture

clippy:
	$ cargo clippy --all-targets -- -D warnings

nargo:
	$ cargo install --force --locked --git https://github.com/lambdaclass/noir --branch fork nargo

