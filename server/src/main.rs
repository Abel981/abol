// use anyhow::Ok;
use server::{Server, HandlerFn};
use radius_core::{Code, HandlerResult, Request, Response, packet::Packet};
use dict_gen::rfc2865::Rfc2865Ext;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let handler = HandlerFn(|request: Request| async move {
        let sec = b"testing123".to_vec();
        println!("Received {} from {}", request.packet.code, request.remote_addr);
      let res =  request.packet.verify_request(&sec);
        let res_packet = request
            .packet
            .create_response(Code::AccessAccept);
        let res = Response::new(res_packet);

        Ok(res)
    });

    let listen_addr = "0.0.0.0:1812";
    let shared_secret = b"testing123".to_vec();

    let server = Server::new(listen_addr, shared_secret, handler);
    println!("Starting Radius server...");

    server.listen_and_serve().await?;
    Ok(())
}