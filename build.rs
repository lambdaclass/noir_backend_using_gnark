fn main() {
    let path = "gnark_backend_ffi";
    let lib = "gnark_backend";

    println!("cargo:rustc-link-search=native={}", path);
    println!("cargo:rustc-link-lib=static={}", lib);
}
