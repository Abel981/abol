# ☕ Abol


<p align="center">
  <b>A high-performance, asynchronous, RADIUS implementation for Rust</b>
</p>

<p align="center">
  Type-safe • Runtime-agnostic • Dictionary-driven
</p>


------------------------------------------------------------------------

## 📖 What is Abol?

**Abol** is a high-performance, asynchronous **RADIUS server
framework** written in Rust.\
It provides a robust, type-safe foundation for building authentication
systems, featuring a powerful **dictionary-driven code generator** for
protocol extensions.

> **What's in a name?**\
> In the traditional Ethiopian coffee ceremony, **Abol** is the first
> round of brewing.\
> It is the strongest, most potent, and most important
> cup---representing clarity and connection.
>
> Like its namesake, this crate serves as the **primary, reliable
> connection point** for your network authentication.

------------------------------------------------------------------------

## ⚡ Why Abol?

-   🚀 **Runtime-Agnostic Core**\
    Optimized for high performance while remaining compatible with
    **Tokio** and **Smol**.

-   🧠 **Zero-Cost Abstractions**\
    Uses Rust's trait system to provide **type-safe attribute access**
    with zero runtime overhead.

-   📚 **Dictionary Power**\
    Turn standard RADIUS dictionary files into **Rust traits**
    automatically at build time.

-   🛡 **Memory Safe**\
    Built 100% in **safe Rust**, protecting your authentication gateway
    from buffer overflows.

------------------------------------------------------------------------

## 🚀 Quick Start

``` toml
[dependencies]
abol = "0.1.0"
tokio = { version = "1", features = ["full"] }
# or
# smol = "1.3"
```

------------------------------------------------------------------------

## 🧪 Example: Simple Auth Server

``` rust
use abol::core::{Request, Response, Code, packet::Packet};
use abol::dictionary::rfc2865Ext;
use abol::server::{Server, HandlerFn}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let handler = HandlerFn(|request: Request| async move {
        // 1. Extraction: Get attributes from the packet using generated traits
        let user_name = request.packet.get_user_name().unwrap_or_else(|| "Unknown".to_string());
        let user_pass = request.packet.get_user_password().unwrap_or_default();

        // 2. Variable for local testing
        let expected_password = "supersecretpassword";

        // 3. Comparison Logic
        // Note: In a real-world scenario, you would perform an async DB lookup here:
        // let user_record = db.find_user(&user_name).await?;
        // if argon2::verify(&user_record.hash, user_pass.as_bytes()) { ... }
        
        if user_pass == expected_password {
            // Create Access-Accept
            let mut res_packet = request.packet.create_response(Code::AccessAccept);
            res_packet.set_reply_message(format!("Hello {}, access granted!", user_name));

            Ok(Response { packet: res_packet })
        } else {
          
            // Create Access-Reject 
            let mut res_packet = request.packet.create_response(Code::AccessReject);
            res_packet.set_reply_message("Invalid credentials provided.");

            Ok(Response { packet: res_packet })
        }
    });

    // 4. Server Initialization
    // Shared secret: "testing123", Listen Address: "0.0.0.0:1812"
    let server = Server::new("0.0.0.0:1812", "testing123", handler);

    println!("Abol RADIUS server is brewing on 0.0.0.0:1812...");
    
    // Run the server
    if let Err(e) = server.listen_and_serve().await {
        eprintln!("Server error: {}", e);
    }

    Ok(())
}
```

------------------------------------------------------------------------

## 📂 Project Architecture

-   **abol-core** -- Packet encoding/decoding and trait definitions\
-   **abol-server** -- Async network layer (multi-runtime compatible)\
-   **abol-dict-gen** -- Build-time dictionary parsing and code
    generation

------------------------------------------------------------------------

## 🗺 Roadmap

-   [ ] RADIUS over TLS (RadSec)
-   [ ] Diameter compatibility layer
-   [ ] Redis / Postgres adapters
-   [ ] Benchmarking against FreeRADIUS

------------------------------------------------------------------------

<p align="center">
  Crafted with ☕ in the spirit of the first brew.
</p>
