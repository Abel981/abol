# ☕ Abol

```{=html}
<p align="center">
  <b>A high-performance, concurrent RADIUS implementation for Rust</b>
</p>

<p align="center">
  Type-safe • Runtime-agnostic • Dictionary-driven
</p>
```

------------------------------------------------------------------------

## 📖 What is Abol?

**Abol** is a high-performance, concurrent **RADIUS server and client
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
    Turn standard RADIUS dictionary files into **idiomatic Rust traits**
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
use abol::{Server, HandlerFn, Request, Response};
use abol::dictionary::rfc2865Ext;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let handler = HandlerFn(|request: Request| async move {
        let user = request.packet.get_user_name().unwrap_or_default();
        let pass = request.packet.get_user_password().unwrap_or_default();

        if user == "abol-user" && pass == "secret" {
            let mut res = request.packet.create_response(2);
            res.set_reply_message("Welcome to the first round!");
            Ok(Response { packet: res })
        } else {
            let res = request.packet.create_response(3);
            Ok(Response { packet: res })
        }
    });

    let server = Server::new("0.0.0.0:1812", b"shared-secret", handler);
    server.listen_and_serve(tokio::signal::ctrl_c()).await?;
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
