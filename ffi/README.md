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

### Calling Go

* Add an `extern` block. For example:

```rust
extern "C" {
    fn Ping(path: GoString) -> *const c_char;
}
```

* Represent io parameter types from Go in Rust as a struct. It needs to match the type definition at byte level.

Example: Go's string
```go
typedef struct { const char *p; ptrdiff_t n; }
```

So in rust:
```rust
#[repr(C)]
struct GoString {
    a: *const c_char,
    b: i64,
}
```

* Call the function inside an unsafe block

```rust
let result = unsafe { Ping(go_string) };
```

### Working with GoString

Convert &str to GoString:
```rust
let c_msg = CString::new(msg).expect("CString::new failed");
let ptr = c_msg.as_ptr();
let go_string = GoString {
    a: ptr,
    b: c_msg.as_bytes().len() as i64,
};
```

Convert GoString to &str:
```rust
let c_str = unsafe { CStr::from_ptr(result) };
let string = c_str.to_str().expect("Error translating Ping from library");
```

## Source

[Calling a Go Library from Rust: A Case Study with SQIP](https://blog.arranfrance.com/post/cgo-sqip-rust/)