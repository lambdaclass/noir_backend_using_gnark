# ffi proof of concept

This proof of concept demonstrates how to call a Go function from Rust.

## Steps

* Create a Go package "main" in a directory {lib_name}
* Mark the functions with `//export {function_name}`
* Compile:

```
$ go build -o lib{lib_name}.so -buildmode=c-shared main.go
```

* Write a build.rs:

```rust
fn main() {
    let path = "./{lib_name}";
    let lib = "{lib_name}";

    println!("cargo:rustc-link-search=native={}", path);
    println!("cargo:rustc-link-lib=static={}", lib);
}
```


## Source

[Calling a Go Library from Rust: A Case Study with SQIP](https://blog.arranfrance.com/post/cgo-sqip-rust/)