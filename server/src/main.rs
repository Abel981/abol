// use anyhow::Ok;
use server::{Server, HandlerFn};
use radius_core::{Code, HandlerResult, Request, Response, packet::Packet};
use dict_gen::rfc2865::Rfc2865Ext;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let handler = HandlerFn(|request: Request| async move {
        println!("Received Request Code: {} from {}", request.packet.code, request.remote_addr);

        // 1. Get User-Name and User-Password
        // The get_user_password() method (if generated) or get_attribute_as::<String>(2)
        // internally uses the decrypt_user_password method we defined in radius_core.
        let user_name = request.packet.get_user_name().unwrap_or_else(|| "Unknown".to_string());
        let user_pass = request.packet.get_user_password(); // Decrypted via trait helper

        match user_pass {
            Some(password) => {
                println!("Login attempt for user: {}", user_name);
                
                // Compare the decrypted password
                if password == "supersecretpassword" {
                    println!("Password match! Sending Access-Accept.");
                    
                    // Create an Access-Accept (Code 2)
                    let mut res_packet = request.packet.create_response(Code::AccessAccept);
                    res_packet.set_reply_message(format!("Hello, {}! Access Granted.", user_name));
                    
                    Ok(Response { packet: res_packet })
                } else {
                    println!("Password mismatch ('{}' != 'supersecretpassword'). Sending Access-Reject.", password);
                    
                    // Create an Access-Reject (Code 3)
                    let res_packet = request.packet.create_response(Code::AccessReject);
                    Ok(Response { packet: res_packet })
                }
            }
            None => {
                println!("No password provided in request.");
                let res_packet = request.packet.create_response(Code::AccessReject);
                Ok(Response { packet: res_packet })
            }
        }
    });

    // Start server on all interfaces, port 1812, secret "testing123"
    let server = Server::new("0.0.0.0:1812", "testing123".to_vec(), handler);
    
    // We pass a simple never-ending future for the shutdown signal for testing
    server.listen_and_serve().await?;
    
    Ok(())
}
