use abol_core::packet::{MAX_PACKET_SIZE, Packet};
use abol_core::{Cidr, Request, Response};
use anyhow::{Context, anyhow};
use bytes::Bytes;
use dashmap::DashSet;
use moka::future::Cache;
use rt::net::AsyncUdpSocket;
use rt::{Executor, Runtime, YieldNow};
use std::error::Error;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

type HandlerResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub(crate) struct RequestKey {
    addr: SocketAddr,
    identifier: u8,
}

/// A provider that maps incoming client IP ranges to their shared secrets.
///
/// In the RADIUS protocol, the server identifies which password (shared secret) 
/// to use based on the source IP address of the Network Access Server (NAS).
///
/// Implement this trait to define how your server looks up these secrets—whether 
/// from a static list, a configuration file, or a database.
pub trait SecretSource: Send + Sync + 'static {
    /// Retrieves a complete list of IP networks and their associated secrets.
    ///
    /// The server's secret manager will call this periodically to refresh its 
    /// internal cache. 
    /// 
    /// ### Returns
    /// A list of tuples where:
    /// * `Cidr` - The IP range (e.g., 192.168.1.0/24) allowed to connect.
    /// * `Vec<u8>` - The shared secret used to sign and encrypt packets for that range.
    fn get_all_secrets(
        &self,
    ) -> impl Future<Output = Result<Vec<(Cidr, Vec<u8>)>, BoxError>> + Send;
}

pub trait SecretSourceExt: Send + Sync + 'static {
    fn get_all_secrets_boxed(&self) -> BoxFuture<'_, Result<Vec<(Cidr, Vec<u8>)>, BoxError>>;
}

impl<T: SecretSource> SecretSourceExt for T {
    fn get_all_secrets_boxed(&self) -> BoxFuture<'_, Result<Vec<(Cidr, Vec<u8>)>, BoxError>> {
        Box::pin(self.get_all_secrets())
    }
}

pub trait SecretProvider: Send + Sync + 'static {
    fn get_secret(&self, client_ip: IpAddr) -> impl Future<Output = Option<Arc<[u8]>>> + Send;
}

pub trait SecretProviderExt: Send + Sync + 'static {
    fn get_secret_boxed(&self, client_ip: IpAddr) -> BoxFuture<'_, Option<Arc<[u8]>>>;
}

impl<T: SecretProvider> SecretProviderExt for T {
    fn get_secret_boxed(&self, client_ip: IpAddr) -> BoxFuture<'_, Option<Arc<[u8]>>> {
        Box::pin(self.get_secret(client_ip))
    }
}

pub struct SecretManager {
    cache: Cache<(), Arc<Vec<(Cidr, Arc<[u8]>)>>>,
    source: Arc<dyn SecretSourceExt>,
}

impl SecretManager {
    pub fn new(source: Arc<dyn SecretSourceExt>, cache_ttl_secs: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(1)
            .time_to_live(std::time::Duration::from_secs(cache_ttl_secs))
            .build();
        Self { cache, source }
    }

    async fn get_secret_internal(&self, client_ip: IpAddr) -> Option<Arc<[u8]>> {
        let table = self
            .cache
            .get_with((), async { self.reload().await.unwrap_or_default() })
            .await;

        table
            .iter()
            .find(|(cidr, _)| cidr.contains(&client_ip))
            .map(|(_, secret)| secret.clone())
    }

    async fn reload(&self) -> Result<Arc<Vec<(Cidr, Arc<[u8]>)>>, BoxError> {
        let entries = self.source.get_all_secrets_boxed().await?;
        let arc_entries = entries
            .into_iter()
            .map(|(cidr, secret)| (cidr, Arc::from(secret)))
            .collect();
        Ok(Arc::new(arc_entries))
    }
}

impl SecretProvider for SecretManager {
    async fn get_secret(&self, client_ip: IpAddr) -> Option<Arc<[u8]>> {
        self.get_secret_internal(client_ip).await
    }
}

pub trait Handler: Send + Sync + 'static {
    fn handle(
        &self,
        request: Request,
    ) -> impl std::future::Future<Output = HandlerResult<Response>> + Send;
}

pub struct HandlerFn<F>(pub F);

impl<F, Fut> Handler for HandlerFn<F>
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = HandlerResult<Response>> + Send + 'static,
{
    async fn handle(&self, request: Request) -> HandlerResult<Response> {
        (self.0)(request).await
    }
}

pub(crate) struct ServerContext<S, H>
where
    S: SecretProvider,
    H: Handler,
{
    pub secret_provider: Arc<S>,
    pub handler: Arc<H>,
    pub undergoing_requests: Arc<DashSet<RequestKey>>,
    pub active_tasks: Arc<AtomicUsize>,
}

pub struct Server<S, H, R>
where
    S: SecretProvider,
    H: Handler,
    R: Runtime,
{
    runtime: Arc<R>,
    socket: Arc<R::Socket>,
    secret_provider: Arc<S>,
    handler: Arc<H>,
    undergoing_requests: Arc<DashSet<RequestKey>>,
    active_tasks: Arc<AtomicUsize>,
    shutdown_signal: Option<BoxFuture<'static, ()>>,
}

impl<S, H, R> Server<S, H, R>
where
    S: SecretProvider + 'static,
    H: Handler + 'static,
    R: Runtime + 'static,
{
    pub fn new(runtime: R, socket: R::Socket, secret_provider: S, handler: H) -> Self {
        Self {
            runtime: Arc::new(runtime),
            socket: Arc::new(socket),
            secret_provider: Arc::new(secret_provider),
            handler: Arc::new(handler),
            undergoing_requests: Arc::new(DashSet::new()),
            active_tasks: Arc::new(AtomicUsize::new(0)),
            shutdown_signal: None,
        }
    }

    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        self.socket.local_addr().map_err(|e| anyhow!(e))
    }

    pub fn with_graceful_shutdown<F>(mut self, shutdown: F) -> Self
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        self.shutdown_signal = Some(Box::pin(shutdown));
        self
    }

    /// Starts the RADIUS server and begins listening for incoming packets.
///
/// This is the main entry point of the server. It will run indefinitely until:
/// 1. An unrecoverable network error occurs.
/// 2. The `shutdown_signal` (if provided) is triggered.
///
/// ### Graceful Shutdown
/// When a shutdown signal is received, the server stops accepting new packets 
/// immediately but waits for all currently processing requests (active tasks) 
/// to finish before returning. This ensures no client requests are "dropped" 
/// mid-processing.
///
/// # Errors
/// Returns an error if the server fails to retrieve the local address or if
/// the internal run loop encounters a fatal exception.
    pub async fn listen_and_serve(self) -> anyhow::Result<()> {
        let local_addr_str = self.socket.local_addr()?.to_string();
        let context = Arc::new(ServerContext {
            secret_provider: Arc::clone(&self.secret_provider),
            handler: Arc::clone(&self.handler),
            undergoing_requests: Arc::clone(&self.undergoing_requests),
            active_tasks: Arc::clone(&self.active_tasks),
        });

        let mut shutdown = self
            .shutdown_signal
            .unwrap_or_else(|| Box::pin(std::future::pending()));

        let mut run_loop_fut = Box::pin(Self::run_loop(
            Arc::clone(&context),
            Arc::clone(&self.socket),
            Arc::clone(&self.runtime),
            local_addr_str,
        ));

        let result = std::future::poll_fn(|cx| {
            if shutdown.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ok(()));
            }
            if let Poll::Ready(res) = run_loop_fut.as_mut().poll(cx) {
                return Poll::Ready(res);
            }
            Poll::Pending
        })
        .await;

        while context.active_tasks.load(Ordering::SeqCst) > 0 {
            YieldNow::new().await;
        }
        result
    }

    async fn run_loop(
        context: Arc<ServerContext<S, H>>,
        socket: Arc<R::Socket>,
        runtime: Arc<R>,
        local_addr: String,
    ) -> anyhow::Result<()> {
        loop {
            let mut buf = [0u8; MAX_PACKET_SIZE];
            let (len, peer_addr) = socket
                .recv_from(&mut buf)
                .await
                .context("Failed to receive")?;

            let data = Bytes::copy_from_slice(&buf[..len]);
            let ctx = Arc::clone(&context);
            let sock = Arc::clone(&socket);
            let l_addr = local_addr.clone();
            let rt = Arc::clone(&runtime);

            ctx.active_tasks.fetch_add(1, Ordering::SeqCst);

            rt.executor().execute(Box::pin(async move {
                let _guard = TaskGuard::new(Arc::clone(&ctx));

                let secret = match ctx.secret_provider.get_secret(peer_addr.ip()).await {
                    Some(s) => s,
                    None => return,
                };

                let packet = match Packet::parse_packet(data, Arc::clone(&secret)) {
                    Ok(p) => p,
                    Err(_) => return,
                };

                let key = RequestKey {
                    addr: peer_addr,
                    identifier: packet.identifier,
                };
                if !ctx.undergoing_requests.insert(key.clone()) {
                    return;
                }

                let _ = Self::process(&ctx, packet, l_addr, peer_addr, sock).await;
                ctx.undergoing_requests.remove(&key);
            }));
        }
    }

    async fn process(
        ctx: &ServerContext<S, H>,
        packet: Packet,
        local_addr: String,
        peer_addr: SocketAddr,
        socket: Arc<R::Socket>,
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
