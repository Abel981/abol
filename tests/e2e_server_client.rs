#![cfg(feature = "tokio")]
#![cfg(test)]

use bytes::Bytes;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket as TokioUdpSocket;

// 1. IMPORTANT: Import the trait to make .local_addr() work
use abol_rt::net::AsyncUdpSocket;
use abol_rt::{Executor, Runtime};
use abol_util::rt::tokio::TokioRuntime;

// RADIUS Protocol imports
use abol_codegen::rfc2865::Rfc2865Ext;
use abol_core::attribute::Attributes;
use abol_core::packet::Packet;
use abol_core::{Cidr, Code, Request, Response};

// Server crate imports
use abol_server::{BoxError, HandlerFn, SecretManager, SecretSource, Server};

/// Mock provider for the shared secret
struct MySecretProvider;

impl SecretSource for MySecretProvider {
    async fn get_all_secrets(&self) -> Result<Vec<(Cidr, Vec<u8>)>, BoxError> {
        Ok(vec![(
            Cidr {
                ip: "127.0.0.1".parse().unwrap(),
                prefix: 32,
            },
            b"secret".to_vec(),
        )])
    }
}

#[tokio::test]
async fn test_access_request_e2e() {
    // --- SETUP ---
    let shared_secret: Arc<[u8]> = Arc::from(b"secret".as_slice());
    let secret_manager = SecretManager::new(Arc::new(MySecretProvider), 3600);

    let runtime = TokioRuntime::new();
    let addr = "127.0.0.1:0".parse().unwrap();

    // 2. Clone the executor BEFORE moving the runtime into the server
    let executor = runtime.executor().clone();

    // 3. Bind the socket using the runtime
    let socket = runtime.bind(addr).await.expect("Failed to bind socket");

    // This works now because AsyncUdpSocket is in scope
    let target_addr = socket.local_addr().expect("Failed to get local address");

    // Define the handler logic
    let handler = HandlerFn(|request: Request| async move {
        let name = request.packet.get_user_name().unwrap_or_default();
        let code = if name == "admin" {
            Code::AccessAccept
        } else {
            Code::AccessReject
        };
        Ok(Response {
            packet: request.packet.create_response_packet(code),
        })
    });

    // 4. Initialize Server (moves runtime and socket)
    let server = Server::new(runtime, socket, secret_manager, handler);

    // 5. Spawn the server using our cloned executor
    executor.execute(Box::pin(async move {
        let _ = server.listen_and_serve().await;
    }));

    // Give the server a moment to start listening
    tokio::time::sleep(Duration::from_millis(50)).await;

    // --- CLIENT: SEND REQUEST ---
    let client_sock = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();

    let mut req_packet = Packet {
        code: Code::AccessRequest,
        identifier: 1,
        authenticator: [0x11; 16],
        attributes: Attributes::default(),
        secret: shared_secret.clone(),
    };
    req_packet.set_user_name("admin".to_string());

    let data = req_packet.encode().unwrap();
    client_sock.send_to(&data, &target_addr).await.unwrap();

    // --- CLIENT: RECEIVE RESPONSE ---
    let mut buf = [0u8; 2048];
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), client_sock.recv_from(&mut buf))
        .await
        .expect("Test timed out waiting for RADIUS response")
        .expect("Failed to receive data");

    let response =
        Packet::parse_packet(Bytes::copy_from_slice(&buf[..len]), shared_secret).unwrap();

    // --- ASSERTIONS ---
    assert_eq!(
        response.code,
        Code::AccessAccept,
        "Server should have accepted 'admin' user"
    );
    assert_eq!(
        response.identifier, 1,
        "Response identifier must match request"
    );
}
