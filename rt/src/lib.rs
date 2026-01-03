use std::pin::Pin;

mod io;
pub mod net;
mod timer;

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

// pub fn get_executor() -> Box<dyn Executor> {
//     #[cfg(feature = "tokio")]
//     {
//         Box::new(TokioExecutor)
//     }
//     #[cfg(feature = "smol")]
//     {
//         Box::new(SmolExecutor)
//     }
// }
