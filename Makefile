build:
	$ cd ./gnark_backend_ffi; \
		go build -o libgnark_backend.so -buildmode=c-shared ./main.go
	$ cargo build

test: build
	$ DYLD_LIBRARY_PATH=./gnark_backend_ffi cargo test

clippy:
	$ cargo clippy --all-targets -- -D warnings
