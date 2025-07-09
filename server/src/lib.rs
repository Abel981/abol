use radius_core::{Request, Response};
use std::ops::Deref;

use anyhow::Context;

//TODO check if the type of handler is correct

struct Server<'a> {
    addr: &'a str,
    shared_secret: &'a [u8],
    handler: Box<dyn Fn(Request) -> Response + 'a>,
}

impl<'a> Server<'a> {
    pub fn new(
        addr: &'a str,
        shared_secret: &'a [u8],
        handler: Box<dyn Fn(Request) -> Response + 'a>,
    ) -> Self {
        if addr.is_empty() {
            panic!()
        }

        Server {
            addr,
            shared_secret,
            handler,
        }
    }

    pub async fn listen_and_serve(&self) -> anyhow::Result<()> {
        let socket = rt::net::UdpSocket::bind(self.addr)
            .await
            .with_context(|| format!("Failed to bind UDP socket to address: {}", self.addr))?;
        println!("RADIUS Server listening on {}", self.addr);

        loop {
            //TODO check buf size is correct and error free
            let mut buf = [0u8; 4096];
            let (len, peer_addr) = socket
                .recv_from(&mut buf)
                .await
                .with_context(|| "Failed to receive data from UDP socket")?;

            let executor = rt::get_executor();

            executor.execute(Box::pin(async {}));
        }
    }
}
