use abol::codegen::rfc2865::Rfc2865Ext;
use abol::core::{Cidr, Code, Request, Response};
use abol::server::{HandlerFn, SecretManager, SecretSource, Server};
use abol_util::rt::smol::SmolRuntime;
use rt::Runtime;
use std::net::SocketAddr;
use std::sync::Arc;
/// A simple static source for RADIUS shared secrets.
/// A simple "Global Password" provider for your RADIUS server.
///
/// Use this if you want every single client (NAS) to use the same shared secret,
/// regardless of their IP address. It is the easiest way to get started.
pub struct StaticSecretSource {
    /// The shared secret (password) used to authenticate RADIUS packets.
    pub secret: Vec<u8>,
}

impl SecretSource for StaticSecretSource {
    /// Tells the server to use the same secret for the entire internet.
    async fn get_all_secrets(
        &self,
    ) -> Result<Vec<(Cidr, Vec<u8>)>, Box<dyn std::error::Error + Send + Sync>> {
        // Define a "Catch-All" range.
        // 0.0.0.0 with a prefix of 0 matches ANY incoming IPv4 address.
        let cidr = Cidr {
            ip: "0.0.0.0".parse()?,
            prefix: 0,
        };

        // Return the mapping: (Everywhere on IPv4) -> (Our Secret)
        Ok(vec![(cidr, self.secret.clone())])
    }
}
// This is using the `smol` runtime. You'll need the following dependency:
//
// `smol = { version = "2" }`
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = "0.0.0.0:1812".parse()?;
    smol::block_on(async {
        // 1. Setup the Secret Manager
        let source = Arc::new(StaticSecretSource {
            secret: b"testing123".to_vec(),
        });
        let secret_manager = SecretManager::new(source, 3600);

        // 2. Define the Request Handler
        let handler = HandlerFn(|request: Request| async move {
            let name = request
                .packet
                .get_user_name()
                .unwrap_or_else(|| "Guest".to_string());
            let pass = request.packet.get_user_password();

            match pass {
                Some(p) if p.as_bytes() == b"supersecretpassword" => {
                    let mut res = request.packet.create_response(Code::AccessAccept);
                    res.set_reply_message(format!("Hello {} (via smol), access granted!", name));
                    Ok(Response { packet: res })
                }
                _ => {
                    let res = request.packet.create_response(Code::AccessReject);
                    Ok(Response { packet: res })
                }
            }
        });

        // 3. Start the Server
        let runtime = SmolRuntime::new();
        let socket = runtime.bind(addr).await?;

        // 4. Create and start the server
        let server = Server::new(runtime, socket, secret_manager, handler);

        server.listen_and_serve().await?;
        println!("Abol (Smol) listening on {}", addr);

        Ok(())
    })
}
