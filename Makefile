LIB_PATH='./gnark_backend_ffi'

build-go:
	$ cd ${LIB_PATH}; \
		go build -buildmode=c-archive -o libgnark_backend.a main.go

build: build-go
	$ cargo build

test: build-go
	$ cargo test

clippy:
	$ cargo clippy --all-targets -- -D warnings
