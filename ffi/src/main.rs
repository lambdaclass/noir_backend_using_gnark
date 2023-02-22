use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use base64::encode;

extern "C" {
    fn Ping(msg: GoString) -> *const c_char;
}

#[repr(C)]
struct GoString {
    a: *const c_char,
    b: i64,
}

#[derive(Debug)]
pub enum PingError {
    Error,
}

pub fn ping(msg: &str) -> Result<&str, PingError> {
    let c_msg = CString::new(msg).expect("CString::new failed");
    let ptr = c_msg.as_ptr();
    let go_string = GoString {
        a: ptr,
        b: c_msg.as_bytes().len() as i64,
    };
    let result = unsafe { Ping(go_string) };
    let c_str = unsafe { CStr::from_ptr(result) };
    let string = c_str.to_str().expect("Error translating Ping from library");
    match string.is_empty() || string.starts_with("Error") {
        true => Err(PingError::Error),
        false => Ok(string),
    }
}

fn main() {
    let result = ping("hello").unwrap();
    println!("{}", result);

    let result = ping("ping").unwrap();
    println!("{}", result);
}
