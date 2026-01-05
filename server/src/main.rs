use std::sync::Arc;

use abol_codegen::rfc2865::Rfc2865Ext;
use abol_core::{Code, Request, Response};
use async_trait::async_trait;
use server::{Cidr, HandlerFn, SecretManager, SecretSource, Server};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pub struct StaticSecretSource {
        pub secret: Vec<u8>,
    }
    #[async_trait]
    impl SecretSource for StaticSecretSource {
        async fn get_all_secrets(
            &self,
        ) -> Result<Vec<(Cidr, Vec<u8>)>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(vec![(
                Cidr {
                    ip: "0.0.0.0".parse()?,
                    prefix: 0,
                },
                self.secret.clone(),
            )])
        }
    }
    let source = Arc::new(StaticSecretSource {
        secret: b"testing123".to_vec(),
    });
    let secret_manager = SecretManager::new(source, 3600);
    let handler = HandlerFn(|request: Request| async move {
        println!(
            "Received Request Code: {} from {}",
            request.packet.code, request.remote_addr
        );

        // 1. Get User-Name and User-Password
        // The get_user_password() method (if generated) or get_attribute_as::<String>(2)
        // internally uses the decrypt_user_password method we defined in radius_core.
        let user_name = request
            .packet
            .get_user_name()
            .unwrap_or_else(|| "Unknown".to_string());
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
                    println!(
                        "Password mismatch ('{}' != 'supersecretpassword'). Sending Access-Reject.",
                        password
                    );

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
    let server = Server::new("0.0.0.0:1812", secret_manager, handler);

    // We pass a simple never-ending future for the shutdown signal for testing
    server
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            println!("Shutdown signal received, starting cleanup...");
        })
        .listen_and_serve()
        .await?;

    Ok(())
}
