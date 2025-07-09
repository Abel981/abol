#[cfg(not(any(feature = "client", feature = "server")))]
compile_error!(
    "You must enable at least one feature from 'client' or 'server' for 'radius-protocol'. \
     Example: `radius-protocol = { version = \"1.0\", features = [\"client\"] }` \
     or `radius-protocol = { version = \"1.0\", features = [\"client\", \"server\"] }`"
);

#[cfg(not(any(feature = "tokio", feature = "smol")))] // Add other runtimes here
compile_error!(
    "You must enable at least one runtime feature (e.g., 'tokio' or 'smol') for 'radius-protocol'. \
     Example: `radius-protocol = { version = \"1.0\", features = [\"tokio\"] }`"
);

pub mod client {
    pub use client::*;
}

pub mod server {
    pub use server::*;
}

pub mod core {
    pub use core::*;
}
