use async_trait::async_trait;
use rt::{Executor, Runtime, net::AsyncUdpSocket};
use std::net::SocketAddr;

#[non_exhaustive]
#[derive(Default, Debug, Clone)]
pub struct SmolExecutor {}

impl Executor for SmolExecutor {
    fn execute<Fut>(&self, fut: Fut)
    where
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        smol::spawn(fut).detach();
    }
}
impl SmolExecutor {
    /// Create new executor that relies on [`tokio::spawn`] to execute futures.
    pub fn new() -> Self {
        Self {}
    }
}

pub struct SmolSocket(pub ::smol::net::UdpSocket);

#[async_trait]
impl AsyncUdpSocket for SmolSocket {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.local_addr()
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        self.0.send_to(buf, target).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.0.recv_from(buf).await
    }
}

pub struct SmolRuntime {
    executor: SmolExecutor,
}

impl SmolRuntime {
    /// Create a new TokioRuntime with its executor.
    pub fn new() -> Self {
        Self {
            executor: SmolExecutor::new(),
        }
    }
}

#[async_trait]
impl Runtime for SmolRuntime {
    type Socket = SmolSocket;
    type Executor = SmolExecutor;

    fn executor(&self) -> &Self::Executor {
        &self.executor
    }

    async fn bind(&self, addr: SocketAddr) -> std::io::Result<Self::Socket> {
        // smol::net::UdpSocket::bind handles setting non-blocking automatically
        let socket = ::smol::net::UdpSocket::bind(addr).await?;
        Ok(SmolSocket(socket))
    }
}
