mod io;
mod timer;

trait Executor {
    fn execute<F>(&self, future: F)
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static;
}

#[cfg(feature = "tokio")]
pub struct TokioExecutor;

impl Executor for TokioExecutor {
    fn execute<F>(&self, future: F)
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let _ = tokio::spawn(future);
    }
}
