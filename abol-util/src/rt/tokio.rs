use std::{
    future::Future,
    io::Result,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use pin_project_lite::pin_project;
use rt::timer::{Sleep, Timer};
use rt::{Executor, Runtime, net::AsyncUdpSocket};

/// Future executor that utilises `tokio` threads.
#[non_exhaustive]
#[derive(Default, Debug, Clone)]
pub struct TokioExecutor {}

/// A Timer that uses the tokio runtime.
#[non_exhaustive]
#[derive(Default, Clone, Debug)]
pub struct TokioTimer;

// Use TokioSleep to get tokio::time::Sleep to implement Unpin.
// see https://docs.rs/tokio/latest/tokio/time/struct.Sleep.html
pin_project! {
    #[derive(Debug)]
    struct TokioSleep {
        #[pin]
        inner: tokio::time::Sleep,
    }
}

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
    /// Create new executor that relies on [`tokio::spawn`] to execute futures.
    pub fn new() -> Self {
        Self {}
    }
}

impl Timer for TokioTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
        Box::pin(TokioSleep {
            inner: tokio::time::sleep(duration),
        })
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
        Box::pin(TokioSleep {
            inner: tokio::time::sleep_until(deadline.into()),
        })
    }

    fn reset(&self, sleep: &mut Pin<Box<dyn Sleep>>, new_deadline: Instant) {
        if let Some(sleep) = sleep.as_mut().downcast_mut_pin::<TokioSleep>() {
            sleep.reset(new_deadline)
        }
    }

    fn now(&self) -> Instant {
        tokio::time::Instant::now().into()
    }
}

impl TokioTimer {
    /// Create a new TokioTimer
    pub fn new() -> Self {
        Self {}
    }
}

impl Future for TokioSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().inner.poll(cx)
    }
}

impl Sleep for TokioSleep {}

impl TokioSleep {
    fn reset(self: Pin<&mut Self>, deadline: Instant) {
        self.project().inner.as_mut().reset(deadline.into());
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
