use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
mod io;
pub mod net;
pub mod timer;

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

// futures::future::

pub enum Executor {
    #[cfg(feature = "tokio")]
    TokioExecutor,
    #[cfg(feature = "smol")]
    SmolExecutor,
}

impl Executor {
    #[cfg(feature = "tokio")]
    pub fn execute(future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>) {
        tokio::spawn(future);
    }
    #[cfg(feature = "smol")]
    pub fn execute(future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>) {
        smol::spawn(future);
    }
}

#[cfg(feature = "tokio")]
pub struct TokioExecutor;

#[cfg(feature = "smol")]
pub struct SmolExecutor;

pub fn get_executor() -> Executor {
    #[cfg(feature = "tokio")]
    {
        Executor::TokioExecutor
    }
    #[cfg(feature = "smol")]
    {
        Executor::SmolExecutor
    }
}
