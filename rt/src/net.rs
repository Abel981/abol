enum UdpSocket {
    #[cfg(feature = "tokio")]
    TokioUdpSocket(tokio::net::UdpSocket),
    #[cfg(feature = "smol")]
    SmolUdpSocket(smol::net::UdpSocket),
}

impl UdpSocket {
    #[cfg(feature = "tokio")]
    async fn bind(addr: impl tokio::net::ToSocketAddrs + Send) -> anyhow::Result<Self> {
        {
            let socket = tokio::net::UdpSocket::bind(addr).await?;
            return Ok(UdpSocket::TokioUdpSocket(socket));
        }
    }
    #[cfg(feature = "smol")]
    async fn bind(addr: impl ToSocketAddrs + Send) -> anyhow::Result<Self> {
        {
            let socket = smol::net::UdpSocket::bind(addr).await?;
            return Ok(UdpSocket::SmolUdpSocket(socket));
        }
    }

    async fn recv_from(&mut self, buf: &mut [u8]) -> anyhow::Result<(usize, std::net::SocketAddr)> {
        match self {
            #[cfg(feature = "tokio")]
            UdpSocket::TokioUdpSocket(socket) => socket.recv_from(buf).await.map_err(Into::into),
            #[cfg(feature = "smol")]
            UdpSocket::SmolUdpSocket(socket) => socket.recv_from(buf).await.map_err(Into::into),
        }
    }
}
