use async_trait::async_trait;
use std::io::Result;
use std::net::SocketAddr;

#[async_trait]
pub trait AsyncUdpSocket: Send + Sync {
    /// Returns the local address this socket is bound to.
    fn local_addr(&self) -> Result<SocketAddr>;

    /// Sends data to the given target address.
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize>;

    /// Receives data from the socket, returning the number of bytes and the source address.
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;
}

