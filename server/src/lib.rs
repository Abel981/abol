use anyhow::Context;
use radius_core::{Request, Response, packet::Packet};
// use tokio::net::UdpSocket;
use rt::Executor;
use rt::net::UdpSocket;

/*
pub struct Server<H>
where
    H: Fn(Request) -> Response + Send + Sync + 'static,
{
    addr: String,
    shared_secret: Vec<u8>,
    handler: H,
}

impl<H> Server<H>
where
    H: Fn(Request) -> Response + Send + Sync + 'static,
{
    pub fn new(addr: impl Into<String>, shared_secret: impl Into<Vec<u8>>, handler: H) -> Self {
        let addr = addr.into();
        if addr.is_empty() {
            panic!("Address cannot be empty");
        }

        Self {
            addr,
            shared_secret: shared_secret.into(),
            handler,
        }
    }

    pub async fn listen_and_serve(&self) -> anyhow::Result<()> {
        let socket = UdpSocket::bind(&self.addr)
            .await
            .with_context(|| format!("Failed to bind UDP socket to {}", self.addr))?;

        println!("RADIUS server listening on {}", self.addr);

        let mut buf = [0u8; 4096];

        loop {
            let (len, peer_addr) = socket
                .recv_from(&mut buf)
                .await
                .context("Failed to receive data")?;

            let packet_data = &buf[..declared_len];

            // Parse request
            let request = match Request::from_bytes(packet_data, &self.shared_secret) {
                Ok(req) => req,
                Err(e) => {
                    println!("Failed to decode packet from {}: {:?}", peer_addr, e);
                    continue;
                }
            };

            // Call user's handler
            let response = (self.handler)(request);

            // Encode response
            let encoded = match response.to_bytes() {
                Ok(b) => b,
                Err(e) => {
                    println!("Failed to encode response: {:?}", e);
                    continue;
                }
            };

            // Send back to client
            if let Err(e) = socket.send_to(&encoded, peer_addr).await {
                println!("Failed to send response: {:?}", e);
            }
        }
    }
}
 */
