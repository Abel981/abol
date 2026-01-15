use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::net::SocketAddr;

use async_trait::async_trait;

use crate::net::AsyncUdpSocket;
pub mod net;
/// A trait defining the asynchronous execution and networking environment.
///
/// This trait abstracts over different async runtimes (e.g., Tokio, Smol),
/// allowing the server logic to remain independent of the underlying event loop.
///
/// Implementers must ensure that both the socket and executor types are
/// compatible with the chosen async reactor.
#[async_trait]
pub trait Runtime: Send + Sync + 'static {
    /// The asynchronous UDP socket type associated with this runtime.
    type Socket: AsyncUdpSocket;

    /// The task executor used to spawn background futures.
    type Executor: Executor;

    /// Returns a reference to the runtime's task executor.
    ///
    /// This is used by the server to spawn concurrent packet-handling tasks.
    fn executor(&self) -> &Self::Executor;

    /// Binds a new asynchronous UDP socket to the specified address.
    ///
    /// # Errors
    ///
    /// Returns an [`std::io::Result`] if the socket cannot be bound,
    /// typically due to the address being in use or invalid permissions.
    async fn bind(&self, addr: SocketAddr) -> std::io::Result<Self::Socket>;
}
pub trait Executor {
    /// Place the future into the executor to be run.
    fn execute<Fut>(&self, fut: Fut)
    where
        Fut: std::future::Future<Output = ()> + Send + 'static;
}
pub struct YieldNow {
    yielded: bool,
}

impl YieldNow {
    pub fn new() -> Self {
        Self { yielded: false }
    }
}
impl Default for YieldNow {
    fn default() -> Self {
        Self::new()
    }
}

impl Future for YieldNow {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}
