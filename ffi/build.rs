fn main() {
    let path = "./ping";
    let lib = "ping";

    println!("cargo:rustc-link-search=native={}", path);
    println!("cargo:rustc-link-lib=static={}", lib);
}
