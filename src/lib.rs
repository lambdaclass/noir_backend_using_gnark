// TODO: This is exposed for testing only, we should find a way to not expose it for
// the users.
pub mod acvm;

pub mod acvm_interop;
pub use acvm_interop::Gnark;

// TODO: This is exposed for testing only, we should find a way to not expose it for
// the users.
pub mod gnark_backend_glue;
