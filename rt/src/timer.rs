use std::{
    pin::Pin,
    time::{Duration, Instant},
};

trait Timer {
    fn sleep(&self, duration: Duration) -> Pin<Box<Sleep>>;
    fn sleep_until(&self, deadline: Instant) -> Pin<Box<Sleep>>;
    fn reset(&self, sleep: &mut Pin<Box<Sleep>>, updated_deadline: Instant) {
        *sleep = self.sleep_until(updated_deadline);
    }
}

type Sleep = dyn Send + Sync + Future<Output = ()>;

#[cfg(feature = "tokio")]
pub struct TokioTimer;

impl Timer for TokioTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<Sleep>> {
        Box::pin(tokio::time::sleep(duration))
    }
    fn sleep_until(&self, deadline: Instant) -> Pin<Box<Sleep>> {
        Box::pin(tokio::time::sleep_until(Instant::into(deadline)))
    }
}
