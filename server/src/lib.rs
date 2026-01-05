use abol_core::packet::{MAX_PACKET_SIZE, Packet};
use abol_core::{HandlerResult, Request, Response};
use anyhow::{Context, anyhow};
use async_trait::async_trait;
use moka::future::Cache;
use rt::net::UdpSocket;
use rt::{Executor, YieldNow};
use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::task::Poll;

type ShutdownFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

pub struct Cidr {
    pub ip: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    /// Checks if a given IP address falls within this CIDR range
    pub fn contains(&self, other: &IpAddr) -> bool {
        match (self.ip, other) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0);
                u32::from(net) & mask == u32::from(*ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix as u32).unwrap_or(0);
                u128::from(net) & mask == u128::from(*ip) & mask
            }
            _ => false,
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
struct RequestKey {
    addr: SocketAddr,
    identifier: u8,
}
#[async_trait]
pub trait SecretProvider: Send + Sync + 'static {
    async fn get_secret(&self, client_ip: IpAddr) -> Option<Arc<[u8]>>;
}

#[async_trait]
impl SecretProvider for SecretManager {
    async fn get_secret(&self, client_ip: IpAddr) -> Option<Arc<[u8]>> {
        self.get_secret(client_ip).await
    }
}

#[async_trait]
pub trait SecretSource: Send + Sync + 'static {
    // Returns a map of CIDR -> Secret.
    // Fetching the whole list is often more efficient for RADIUS than one-by-one.
    async fn get_all_secrets(
        &self,
    ) -> Result<Vec<(Cidr, Vec<u8>)>, Box<dyn std::error::Error + Send + Sync>>;
}

pub struct SecretManager {
    cache: Cache<(), Arc<Vec<(Cidr, Arc<[u8]>)>>>,
    source: Arc<dyn SecretSource>,
}

impl SecretManager {
    pub fn new(source: Arc<dyn SecretSource>, cache_ttl_secs: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(1)
            .time_to_live(std::time::Duration::from_secs(cache_ttl_secs))
            .build();
        Self { cache, source }
    }

    pub async fn get_secret(&self, client_ip: IpAddr) -> Option<Arc<[u8]>> {
        let table = self
            .cache
            .get_with((), async { self.reload().await.unwrap_or_default() })
            .await;

        table
            .iter()
            .find(|(cidr, _)| cidr.contains(&client_ip))
            .map(|(_, secret)| Arc::from(secret.clone()))
    }

    async fn reload(
        &self,
    ) -> Result<Arc<Vec<(Cidr, Arc<[u8]>)>>, Box<dyn std::error::Error + Send + Sync>> {
        let entries = self.source.get_all_secrets().await?;
        let arc_entries = entries
            .into_iter()
            .map(|(cidr, secret)| (cidr, Arc::from(secret)))
            .collect();
        Ok(Arc::new(arc_entries))
    }
}

// pub struct StaticSecret(Vec<u8>);
// impl SecretProvider for StaticSecret {
//     fn get_secret(&self, _addr: std::net::SocketAddr) -> Option<Arc<[u8]>> {
//         Some(Arc::from(self.0.clone()))
//     }
// }
// impl StaticSecret {
//     pub fn new(secret: Vec<u8>) -> Self {
//         StaticSecret(secret)
//     }
// }

#[async_trait]
pub trait Handler: Send + Sync + 'static {
    async fn handle(&self, request: Request) -> HandlerResult<Response>;
}

pub struct HandlerFn<F>(pub F);

#[async_trait]
impl<F, Fut> Handler for HandlerFn<F>
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = HandlerResult<Response>> + Send + 'static,
{
    async fn handle(&self, request: Request) -> HandlerResult<Response> {
        (self.0)(request).await
    }
}

pub struct ServerContext<S, H>
where
    S: SecretProvider,
    H: Handler,
{
    pub secret_provider: Arc<S>,
    pub handler: Arc<H>,
    pub undergoing_requests: Arc<RwLock<HashSet<RequestKey>>>,
    pub active_tasks: Arc<AtomicUsize>,
}

pub struct Server<S, H>
where
    S: SecretProvider,
    H: Handler,
{
    addr: String,
    secret_provider: Arc<S>,
    handler: Arc<H>,
    undergoing_requests: Arc<RwLock<HashSet<RequestKey>>>,
    active_tasks: Arc<AtomicUsize>,
    shutdown_signal: Option<ShutdownFuture>,
}

impl<S, H> Server<S, H>
where
    S: SecretProvider,
    H: Handler,
{
    pub fn new(addr: impl Into<String>, secret_provider: S, handler: H) -> Self {
        Self {
            addr: addr.into(),
            secret_provider: Arc::new(secret_provider),
            handler: Arc::new(handler),
            undergoing_requests: Arc::new(RwLock::new(HashSet::new())),
            active_tasks: Arc::new(AtomicUsize::new(0)),
            shutdown_signal: None,
        }
    }

    pub fn with_graceful_shutdown<F>(mut self, shutdown: F) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.shutdown_signal = Some(Box::pin(shutdown));
        self
    }

    pub async fn listen_and_serve(self) -> anyhow::Result<()> {
        let socket = Arc::new(
            UdpSocket::bind(&self.addr)
                .await
                .with_context(|| format!("Failed to bind UDP socket to {}", self.addr))?,
        );

        let local_addr = socket.local_addr()?.to_string();

        let context = Arc::new(ServerContext {
            secret_provider: self.secret_provider,
            handler: self.handler,
            undergoing_requests: self.undergoing_requests,
            active_tasks: self.active_tasks,
        });

        let mut shutdown = self
            .shutdown_signal
            .unwrap_or_else(|| Box::pin(std::future::pending()));
        let mut run_loop_fut = Box::pin(Self::run_loop(
            Arc::clone(&context),
            Arc::clone(&socket),
            local_addr,
        ));

        let result = std::future::poll_fn(|cx| {
            if let Poll::Ready(_) = shutdown.as_mut().poll(cx) {
                return Poll::Ready(Ok(()));
            }
            if let Poll::Ready(res) = run_loop_fut.as_mut().poll(cx) {
                return Poll::Ready(res);
            }
            Poll::Pending
        })
        .await;

        // Wait for background tasks to drain
        while context.active_tasks.load(Ordering::SeqCst) > 0 {
            YieldNow::new().await;
        }

        result
    }

    async fn run_loop(
        context: Arc<ServerContext<S, H>>,
        socket: Arc<UdpSocket>,
        local_addr: String,
    ) -> anyhow::Result<()> {
        loop {
            let mut buf = [0u8; MAX_PACKET_SIZE];
            let (len, peer_addr) = socket
                .recv_from(&mut buf)
                .await
                .context("Failed to receive data")?;

            let data = buf[..len].to_vec();
            let ctx = Arc::clone(&context);
            let sock = Arc::clone(&socket);
            let l_addr = local_addr.clone();

            // Increment before spawning
            ctx.active_tasks.fetch_add(1, Ordering::SeqCst);

            Executor::execute(Box::pin(async move {
                // TaskGuard now takes the whole context Arc to manage the count
                let _guard = TaskGuard::new(Arc::clone(&ctx));

                let secret = match ctx.secret_provider.get_secret(peer_addr.ip()).await {
                    Some(s) => s,
                    None => return,
                };

                let packet = match Packet::parse_packet(&data, Arc::clone(&secret)) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Failed to parse packet from {}: {:?}", peer_addr, e);
                        return;
                    }
                };

                let key = RequestKey {
                    addr: peer_addr,
                    identifier: packet.identifier,
                };

                {
                    let mut ongoing = ctx.undergoing_requests.write().unwrap();
                    if !ongoing.insert(key.clone()) {
                        return;
                    }
                }

                if let Err(e) = Self::process(&ctx, packet, l_addr, peer_addr, sock).await {
                    eprintln!("Error processing request from {}: {:?}", peer_addr, e);
                }

                if let Ok(mut ongoing) = ctx.undergoing_requests.write() {
                    ongoing.remove(&key);
                }
            }));
        }
    }

    async fn process(
        ctx: &ServerContext<S, H>,
        packet: Packet,

        local_addr: String,
        peer_addr: SocketAddr,
        socket: Arc<UdpSocket>,
    ) -> anyhow::Result<()> {
        if !packet.verify_request() {
            return Err(anyhow!("Invalid authenticator from {}", peer_addr));
        }

        let request = Request {
            local_addr,
            remote_addr: peer_addr.to_string(),
            packet,
        };

        let response = ctx
            .handler
            .handle(request)
            .await
            .map_err(|e| anyhow!("Handler error: {:?}", e))?;

        let encoded = response.packet.encode().context("Encoding failed")?;
        socket
            .send_to(&encoded, peer_addr)
            .await
            .context("UDP send failed")?;

        Ok(())
    }
}

/// Guard to ensure active_tasks is decremented even if the task panics or returns early.
struct TaskGuard<S, H>
where
    S: SecretProvider,
    H: Handler,
{
    context: Arc<ServerContext<S, H>>,
}

impl<S, H> TaskGuard<S, H>
where
    S: SecretProvider,
    H: Handler,
{
    fn new(context: Arc<ServerContext<S, H>>) -> Self {
        Self { context }
    }
}

impl<S, H> Drop for TaskGuard<S, H>
where
    S: SecretProvider,
    H: Handler,
{
    fn drop(&mut self) {
        self.context.active_tasks.fetch_sub(1, Ordering::SeqCst);
    }
}
