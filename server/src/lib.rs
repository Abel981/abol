use anyhow::Context;
use async_trait::async_trait;
use radius_core::packet::{MAX_PACKET_SIZE, Packet};
use radius_core::{HandlerResultt};
use radius_core::{Request, Response};
use rt::net::UdpSocket;

#[async_trait]
pub trait Handler: Send + Sync + 'static {
    async fn handler(&self, request: Request) -> HandlerResult<Response>;
}

pub struct HandlerFn<F>(pub F);

#[async_trait]
impl<F, Fut> Handler for HandlerFn<F>
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = HandlerResult<Response>> + Send + 'static,
{
    async fn handler(&self, request: Request) -> HandlerResult<Response> {
        (self.0)(request).await
    }
}

pub struct Server<H>
where
    H: Handler,
{
    addr: String,
    shared_secret: Vec<u8>,
    handler: H,
}

impl<H> Server<H>
where
    H: Handler,
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

        let mut buf = [0u8; MAX_PACKET_SIZE];

        loop {
            let (len, peer_addr) = socket
                .recv_from(&mut buf)
                .await
                .context("Failed to receive data")?;

            let packet_data = &buf[..len];

            // Parse request
            let packet = match Packet::parse_packet(packet_data, &self.shared_secret) {
                Ok(req) => req,
                Err(e) => {
                    println!("Failed to decode packet from {}: {:?}", peer_addr, e);
                    continue;
                }
            };

            println!("[packet: {:?}", packet.identifier);
            let is_packet_valid = packet.verify_request(&self.shared_secret);
            if !is_packet_valid {
                println!("Invalid packet authenticator from {}", peer_addr);
                continue;
            }
            let request = Request {
                local_addr: self.addr.clone(),
                remote_addr: peer_addr.to_string(),
                packet,
            };

            // Call user's handler
            let handler_result = self.handler.handler(request).await;
            let response = match handler_result {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Handler returned an error: {:?}", e);
                    //TODO  Depending on the RADIUS server logic, you might send an Access-Reject
                    // or simply ignore the request and continue the loop.
                    continue;
                }
            };
            let encoded = match response.packet.encode() {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Failed to encode response: {:?}", e);
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
