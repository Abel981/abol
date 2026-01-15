use abol_rt::{Executor, Runtime, net::AsyncUdpSocket};
use async_trait::async_trait;
use std::{io::Result, net::SocketAddr};

/// Future executor that utilizes `tokio` task spawning.
/// Derived Default is idiomatic for stateless executors.
#[non_exhaustive]
#[derive(Default, Debug, Clone)]
pub struct TokioExecutor {}

impl TokioExecutor {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Executor for TokioExecutor {
    fn execute<Fut>(&self, fut: Fut)
    where
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        tokio::spawn(fut);
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

#[derive(Default, Debug, Clone)]
pub struct TokioRuntime {
    executor: TokioExecutor,
}

impl TokioRuntime {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Runtime for TokioRuntime {
    type Socket = TokioSocket;
    type Executor = TokioExecutor;

    fn executor(&self) -> &Self::Executor {
        &self.executor
    }

    async fn bind(&self, addr: SocketAddr) -> Result<Self::Socket> {
        let socket = tokio::net::UdpSocket::bind(addr).await?;
        Ok(TokioSocket(socket))
    }
}
