use async_trait::async_trait;
use rt::{Executor, Runtime, net::AsyncUdpSocket};
use std::net::SocketAddr;

#[non_exhaustive]
#[derive(Default, Debug, Clone)]
pub struct SmolExecutor {}

impl SmolExecutor {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Executor for SmolExecutor {
    fn execute<Fut>(&self, fut: Fut)
    where
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        smol::spawn(fut).detach();
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

#[derive(Default, Debug, Clone)]
pub struct SmolRuntime {
    executor: SmolExecutor,
}

impl SmolRuntime {
    pub fn new() -> Self {
        Self::default()
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
        let socket = ::smol::net::UdpSocket::bind(addr).await?;
        Ok(SmolSocket(socket))
    }
}
