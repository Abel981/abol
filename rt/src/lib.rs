use std::pin::Pin;

mod io;
pub mod net;
mod timer;

pub trait Executor {
    fn execute(&self, future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>);
}

#[cfg(feature = "tokio")]
pub struct TokioExecutor;
#[cfg(feature = "tokio")]
impl Executor for TokioExecutor {
    fn execute(&self, future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>) {
        let _ = tokio::spawn(future);
    }
}

#[cfg(feature = "smol")]
pub struct SmolExecutor;
#[cfg(feature = "smol")]
impl Executor for SmolExecutor {
    fn execute(&self, future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>) {
        let _ = smol::spawn(future);
    }
}

pub fn get_executor() -> Box<dyn Executor> {
    #[cfg(feature = "tokio")]
    {
        Box::new(TokioExecutor)
    }
    #[cfg(feature = "smol")]
    {
        Box::new(SmolExecutor)
    }
}
