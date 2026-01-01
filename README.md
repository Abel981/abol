Abol ☕

Abol is a high-performance, concurrent RADIUS implementation for Rust. It provides a robust, type-safe framework for building RADIUS servers and clients, featuring a powerful code generator for dictionary-driven protocol extensions.

What's in a name? > In the traditional Ethiopian coffee ceremony, Abol is the name given to the first round of brewing. It is the strongest, most potent, and most important cup—representing clear thinking and the initial social connection. Like its namesake, this crate serves as the primary, reliable connection point for your network authentication.

⚡ Why Abol?

Runtime Agnostic Core: While optimized for high performance, the core logic is flexible enough to run on Tokio, Smol.

Zero-Cost Abstractions: Uses Rust's trait system to provide type-safe attribute access without runtime overhead.

Dictionary Power: Turn standard RADIUS dictionary files into idiomatic Rust traits automatically at build time.

Memory Safe: Built 100% in safe Rust, ensuring your authentication gateway is immune to buffer overflows.

🚀 Quick Start

Add abol to your Cargo.toml. Whether you prefer the scale of tokio or the simplicity of smol, Abol fits right in.

[dependencies]
abol = "0.1.0"
tokio = { version = "1", features = ["full"] } # Or smol = "1.3"


Example: Simple Auth Server

use abol::{Server, HandlerFn, Request, Response, Packet};
use abol::dictionary::rfc2865Ext; // Generated extension traits

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let handler = HandlerFn(|request: Request| async move {
        let user = request.packet.get_user_name().unwrap_or_default();
        let pass = request.packet.get_user_password().unwrap_or_default();

        if user == "abol-user" && pass == "secret" {
            let mut res = request.packet.create_response(2); // Access-Accept
            res.set_reply_message("Welcome to the first round!");
            Ok(Response { packet: res })
        } else {
            let res = request.packet.create_response(3); // Access-Reject
            Ok(Response { packet: res })
        }
    });

    let server = Server::new("0.0.0.0:1812", b"shared-secret", handler);
    
    println!("Abol RADIUS server starting on 1812...");
    server.listen_and_serve(tokio::signal::ctrl_c()).await?;
    Ok(())
}


🛠 Features Breakdown

🏗 Dictionary Code Generation

Abol removes the pain of manual byte-offset management. Define your dictionaries, and let the generator handle the rest.

// build.rs
fn main() {
    let generator = abol_gen::Generator::new("radius_types");
    generator.process_files(vec!["./my_custom_rfc.dict"]).unwrap();
}


🔒 Built-in Security

RFC 2865 Compliance: Full support for MD5-XOR user password encryption/decryption.

VSA Support: Robust handling for Vendor-Specific Attributes (Cisco, Microsoft, etc.).

Validation: Automatic packet authenticator verification.

📂 Project Architecture

Abol is modular by design:

abol-core: The heart of the project. Packet encoding/decoding and trait definitions.

abol-server: The async network layer (compatible with multiple runtimes).

abol-dict-gen: The build-time engine for dictionary parsing.

🗺 Roadmap

[ ] Support for RADIUS over TLS (RadSec)

[ ] Diameter protocol compatibility layer

[ ] Redis/Postgres state-store adapters for AppContext

[ ] Benchmarking suite against FreeRADIUS

🤝 Contributing

We welcome contributions from the community! Whether it's a new RFC implementation or a bug fix, feel free to open a PR. Please ensure you run cargo test before submitting.

Crafted with ☕ in the spirit of the first brew.