use anyhow::Result;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

// Assuming these are available in your workspace/crate
use abol_core::attribute::Avp;
use abol_core::packet::Packet;
use abol_core::{Code, HandlerResult, Request, Response};
use rt::Executor;
use server::{HandlerFn, Server, StaticSecret};

#[test]
fn test_radius_server_e2e() -> Result<()> {
    // 1. Setup constants and server configuration
    let bind_addr = "127.0.0.1:18124";
    let shared_secret = b"secret123";

    // We create a provider that simply returns "secret123" for any address
    let secret_provider = StaticSecret::new(shared_secret.clone().to_vec());

    // 2. Define a simple handler logic
    // If the username is "alice", accept; otherwise reject.
    let handler = HandlerFn(|req: Request| async move {
        let username_attr = req
            .packet
            .attributes
            .0
            .iter()
            .find(|a| a.attribute_type == 1); // User-Name is Type 1

        let response_code = match username_attr {
            Some(attr) if attr.value == b"alice" => Code::AccessAccept,
            _ => Code::AccessReject,
        };

        let mut res_packet = req.packet.create_response(response_code);
        // Echo back a custom attribute or just return the packet
        Ok(Response { packet: res_packet })
    });

    // 3. Initialize the server
    let server = Server::new(bind_addr, secret_provider, handler);

    // 4. Start the server in the background using your custom executor
    Executor::execute(Box::pin(async move {
        if let Err(e) = server.listen_and_serve().await {
            eprintln!("Server error: {:?}", e);
        }
    }));

    // Give the server a moment to bind to the socket
    std::thread::sleep(Duration::from_millis(200));

    // 5. Simulate a Client using standard UdpSocket
    let client_sock = UdpSocket::bind("127.0.0.1:0")?;
    client_sock.connect(bind_addr)?;
    client_sock.set_read_timeout(Some(Duration::from_secs(2)))?;

    // 6. Create and send a valid Access-Request
    // Note: Packet::new requires the secret to generate the correct Request Authenticator
    let mut request_packet = Packet::new(Code::AccessRequest, shared_secret);
    request_packet.identifier = 123;
    request_packet.attributes.0.push(Avp {
        attribute_type: 1, // User-Name
        value: b"alice".to_vec(),
    });

    let encoded_req = request_packet.encode()?;
    client_sock.send(&encoded_req)?;

    // 7. Receive response
    let mut buf = [0u8; 4096];
    let (amt, _) = client_sock.recv_from(&mut buf)?;

    // 8. Parse and Validate Response
    // We use the same secret to verify the response authenticator
    let response_packet = Packet::parse_packet(&buf[..amt], shared_secret)
        .map_err(|e| anyhow::anyhow!("Failed to parse response: {:?}", e))?;

    // Assertions
    assert_eq!(
        response_packet.code,
        Code::AccessAccept,
        "Should have accepted 'alice'"
    );
    assert_eq!(response_packet.identifier, 123, "Identifier mismatch");

    println!("E2E Test Passed: Received Access-Accept for user 'alice'");
    Ok(())
}
