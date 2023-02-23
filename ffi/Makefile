build:
	$ cd ./ping; \
		go build -o libping.so -buildmode=c-shared ./main.go
	$ cargo build

run: build
	$ DYLD_LIBRARY_PATH=./ping cargo run
