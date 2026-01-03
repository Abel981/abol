#[cfg(not(any(feature = "server")))]
compile_error!(
    "You must enable server feature for 'abol'. \
     Example: `abol = { version = \"0.1.0\", features = [\"server\"] }`"
);

#[cfg(not(any(feature = "tokio", feature = "smol")))]
compile_error!(
    "You must enable at least one runtime feature (e.g., 'tokio' or 'smol') for 'abol'. \
     Example: `abol = { version = \"0.1.0\", features = [\"tokio\"] }`"
);

pub mod server {
    pub use server::*;
}

pub mod core {
    pub use abol_core::*;
}
pub mod codegen {
    pub use abol_codegen::*;
}
