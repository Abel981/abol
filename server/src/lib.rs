use abol_core::HandlerResult;
use abol_core::packet::{MAX_PACKET_SIZE, Packet};
use abol_core::{Request, Response};
use anyhow::Context;
use async_trait::async_trait;
use rt::Executor;
use rt::net::UdpSocket;
use std::net::SocketAddr;
use std::sync::Arc;

/// Defines how to retrieve a secret based on the client's IP.
pub trait SecretProvider: Send + Sync + 'static {
    fn get_secret(&self, addr: SocketAddr) -> Option<Vec<u8>>;
}

/// Simple implementation for a single global secret.
pub struct StaticSecret(pub Vec<u8>);
impl SecretProvider for StaticSecret {
    fn get_secret(&self, _: SocketAddr) -> Option<Vec<u8>> {
        Some(self.0.clone())
    }
}

#[async_trait]
pub trait Handler: Send + Sync + 'static {
    async fn handle(&self, request: Request) -> HandlerResult<Response>;
}

pub struct HandlerFn<F>(pub F);

#[async_trait]
impl<F, Fut> Handler for HandlerFn<F>
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = HandlerResult<Response>> + Send + 'static,
{
    async fn handle(&self, request: Request) -> HandlerResult<Response> {
        (self.0)(request).await
    }
}

pub struct Server<S, H>
where
    S: SecretProvider,
    H: Handler,
{
    addr: String,
    secret_provider: Arc<S>,
    handler: Arc<H>,
}

impl<S, H> Server<S, H>
where
    S: SecretProvider,
    H: Handler,
{
    /// Creates a new RADIUS server instance.
    ///
    /// # Arguments
    ///
    /// * `addr` - The network address to bind to (e.g., "0.0.0.0:1812").
    /// * `secret_provider` - An implementation of [`SecretProvider`] used to look up shared secrets
    ///   for incoming client requests based on their source IP address.
    /// * `handler` - The business logic handler that processes valid RADIUS requests and
    ///   returns appropriate responses.
    ///
    /// # Panics
    ///
    /// This function will panic if the provided `addr` is an empty string.
    pub fn new(addr: impl Into<String>, secret_provider: S, handler: H) -> Self {
        let addr = addr.into();
        if addr.is_empty() {
            panic!("Address cannot be empty");
        }

        Self {
            addr,
            secret_provider: Arc::new(secret_provider),
            handler: Arc::new(handler),
        }
    }
    /// Listens for incoming RADIUS requests and serves responses to clients.
    ///
    /// From a client's perspective, this method provides a highly available authentication
    /// endpoint. When a client sends a RADIUS packet to this server:
    ///
    /// 1. **Immediate Acceptance**: The server accepts the incoming UDP packet and
    ///    immediately prepares to process the next one, ensuring minimal latency for
    ///    concurrent clients.
    /// 2. **Authentication**: The server validates the client's request using the
    ///    shared secret associated with the client's source IP address.
    /// 3. **Asynchronous Processing**: The server processes the request logic
    ///    independently of other active sessions, allowing for high throughput.
    /// 4. **Reliable Response**: If the request is valid and the handler logic permits,
    ///    the client receives an encoded RADIUS response (e.g., Access-Accept or
    ///    Access-Reject) sent back to its source port.
    ///
    /// # Errors
    ///
    /// Returns an error if the server is unable to bind to the requested port or
    /// encounters a terminal failure in its network interface.
    pub async fn listen_and_serve(&self) -> anyhow::Result<()> {
        let socket = Arc::new(
            UdpSocket::bind(&self.addr)
                .await
                .with_context(|| format!("Failed to bind UDP socket to {}", self.addr))?,
        );

        println!("RADIUS server listening on {}", self.addr);

        loop {
            let mut buf = [0u8; MAX_PACKET_SIZE];
            let (len, peer_addr) = socket
                .recv_from(&mut buf)
                .await
                .context("Failed to receive data")?;

            let socket_clone = Arc::clone(&socket);
            let secret_provider = Arc::clone(&self.secret_provider);
            let handler = Arc::clone(&self.handler);

            // local_addr needs to be called before moving into the task if we don't want to clone the whole socket
            let local_addr = socket.local_addr()?.to_string();

            // We MUST copy the data from the buffer because 'buf' is overwritten in the next iteration
            let data = buf[..len].to_vec();

            Executor::execute(Box::pin(async move {
                let secret = match secret_provider.get_secret(peer_addr) {
                    Some(s) => s,
                    None => {
                        eprintln!("No secret found for client {}", peer_addr);
                        return;
                    }
                };

                // 1. Parse & Verify
                let packet = match Packet::parse_packet(&data, &secret) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Parse error from {}: {}", peer_addr, e);
                        return;
                    }
                };

                if !packet.verify_request(&secret) {
                    eprintln!("Invalid authenticator from {}", peer_addr);
                    return;
                }

                // 2. Handle
                let request = Request {
                    local_addr,
                    remote_addr: peer_addr.to_string(),
                    packet,
                };

                let handler_result = handler.handle(request).await;

                let response = match handler_result {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("Handler returned an error: {:?}", e);
                        return;
                    }
                };

                // 3. Encode & Send
                let encoded = match response.packet.encode() {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("Failed to encode response: {:?}", e);
                        return;
                    }
                };

                if let Err(e) = socket_clone.send_to(&encoded, peer_addr).await {
                    eprintln!("Failed to send response: {:?}", e);
                }
            }));
        }
    }
}
