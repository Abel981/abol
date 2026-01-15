use std::{io::Result, net::SocketAddr};

use async_trait::async_trait;
use rt::{Executor, Runtime, net::AsyncUdpSocket};

/// Future executor that utilises `tokio` threads.
#[non_exhaustive]
#[derive(Default, Debug, Clone)]
pub struct TokioExecutor {}

// ===== impl TokioExecutor =====

impl Executor for TokioExecutor {
    fn execute<Fut>(&self, fut: Fut)
    where
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        tokio::spawn(fut);
    }
}

impl TokioExecutor {
    pub fn new() -> Self {
        Self {}
    }
}

pub struct TokioSocket(pub tokio::net::UdpSocket);

#[async_trait]
impl AsyncUdpSocket for TokioSocket {
    fn local_addr(&self) -> Result<SocketAddr> {
        self.0.local_addr()
    }
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize> {
        self.0.send_to(buf, target).await
    }
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.0.recv_from(buf).await
    }
}
pub struct TokioRuntime {
    executor: TokioExecutor,
}

impl TokioRuntime {
    pub fn new() -> Self {
        Self {
            executor: TokioExecutor::new(),
        }
    }
}

#[async_trait]
impl Runtime for TokioRuntime {
    type Socket = TokioSocket;
    type Executor = TokioExecutor;

    fn executor(&self) -> &Self::Executor {
        &self.executor
    }

    async fn bind(&self, addr: SocketAddr) -> std::io::Result<Self::Socket> {
        // 1. Bind the standard blocking socket
        let std_sock = std::net::UdpSocket::bind(addr)?;

        // 2. CRITICAL: Set it to non-blocking mode for Tokio
        std_sock.set_nonblocking(true)?;

        // 3. Convert to Tokio's async socket
        Ok(TokioSocket(tokio::net::UdpSocket::from_std(std_sock)?))
    }
}
