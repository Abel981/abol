use md5::{Digest, Md5};
use rand::Rng;
use std::io::Cursor;
use thiserror::Error;

use crate::{
    Code,
    attribute::{self, AttributeParseError, AttributeValue, Attributes},
};

pub const MAX_PACKET_SIZE: usize = 4096;
pub struct Packet {
    pub code: Code,
    pub identifier: u8,
    pub authenticator: [u8; 16],
    pub attributes: Attributes,
    pub secret: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum PacketParseError {
    #[error("Packet not at least 20 bytes long")]
    TooShortHeader,
    #[error("unknown packet code")]
    UnknownPacketCode,
    #[error("Invalid packet length: {0}")]
    InvalidLength(usize),
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Attribute parsing failed: {0}")]
    AttributeError(AttributeParseError),
}
impl Packet {
    pub fn new(code: Code, secret: Vec<u8>) -> Self {
        let mut buff = [0u8; 17];
        rand::rng().fill(&mut buff);
        let identifier = buff[0];
        let mut authenticator = [0u8; 16];
        authenticator.copy_from_slice(&buff[1..17]);
        Packet {
            code,
            identifier,
            authenticator,
            attributes: Attributes(Vec::new()),
            secret,
        }
    }

    pub fn parse_packet<'a>(b: &'a [u8], secret: &'a [u8]) -> Result<Self, PacketParseError> {
        if b.len() < 20 || b.len() > MAX_PACKET_SIZE {
            return Err(PacketParseError::TooShortHeader);
        }
        let mut cursor = Cursor::new(b);
        cursor.set_position(2);

        let length = u16::from_be_bytes([b[2], b[3]]);
        let length = usize::from(length);

        if length < 20 || length > MAX_PACKET_SIZE || length > b.len() {
            return Err(PacketParseError::InvalidLength(length));
        }
        let mut authenticator = [0u8; 16];
        authenticator.copy_from_slice(&b[4..20]);
        let attribute_data_slice = &b[20..length];
        let attrs = attribute::parse_attributes(attribute_data_slice)?;
        let code = Code::try_from(b[0])?;
        Ok(Self {
            code,
            identifier: b[1],
            authenticator,
            attributes: attrs, // Attribute parsing can be added here
            secret: secret.to_vec(),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, PacketParseError> {
        // 1. Get the raw packet bytes. The Authenticator field (b[4..20])
        //    is currently populated with the Request Authenticator (or random bytes for requests).
        let mut b = self.encode_raw()?;
        let code: Code = self.code;

        match code {
            // Access-Request and Status-Server use a random Request Authenticator.
            // Since `encode_raw` already placed `self.authenticator` (a random value
            // generated when the Request struct was created) into b[4..20], we are done.
            Code::AccessRequest | Code::StatusServer => Ok(b),

            // These are Response Codes (Access-Accept/Reject, Accounting-Response, etc.)
            // The Authenticator field is calculated as MD5(Packet|RequestAuth|Secret).
            Code::AccessAccept
            | Code::AccessReject
            | Code::AccessChallenge
            | Code::AccountingResponse
            | Code::DisconnectAck
            | Code::DisconnectNak => {
                let mut hasher = Md5::new();

                // 2. Hash the Code, ID, Length (b[0..4])
                hasher.update(&b[0..4]);

                // 3. Hash the Request Authenticator (b[4..20])
                // This is correct because `encode_raw` populated b[4..20] with `self.authenticator`,
                // which must hold the Request Authenticator for a response packet.
                hasher.update(&b[4..20]);

                // 4. Hash the Attributes (b[20..])
                hasher.update(&b[20..]);

                // 5. Hash the Shared Secret
                hasher.update(&self.secret);

                // 6. Calculate the final hash and place it back into b[4..20] (Response Authenticator)
                let hash_result = hasher.finalize();
                b[4..20].copy_from_slice(&hash_result);

                Ok(b)
            }

            // These are Request Codes (Accounting-Request, Disconnect-Request, CoA-Request)
            // These require the Message-Authenticator attribute (Type 80) for signing.
            // The MD5 calculation here is for the Message-Authenticator attribute, NOT the
            // primary Authenticator field (b[4..20]), which should be zeroed out in the hash calculation.
            // Your original Go logic seems to be trying to implement the Message-Authenticator check.
            Code::AccountingRequest | Code::DisconnectRequest | Code::CoARequest => {
                // If you are using Message-Authenticator, this logic is correct:
                // MD5(Code|ID|Length|0x00*16|Attributes|Secret)
                // However, the result of this hash must be placed in the Message-Authenticator attribute,
                // and the *primary* Authenticator field must be set to the hash of the original
                // Request Authenticator and other fields (which is complex).

                // Sticking to your original attempt to fix the primary authenticator field:

                let mut hasher = Md5::new();
                hasher.update(&b[0..4]);

                // Zero out the Authenticator field for the hash calculation
                const NUL_AUTHENTICATOR: [u8; 16] = [0u8; 16];
                hasher.update(NUL_AUTHENTICATOR);

                hasher.update(&b[20..]);
                hasher.update(&self.secret);

                // The result of this hash should typically go into the Message-Authenticator attribute
                // for these packet types, but your code places it into b[4..20].
                // We will follow your code structure for now.
                let hash_result = hasher.finalize();
                b[4..20].copy_from_slice(&hash_result);

                Ok(b)
            }

            _ => Err(PacketParseError::UnknownPacketCode),
        }
    }
    pub fn encode_raw(&self) -> Result<Vec<u8>, PacketParseError> {
        let attributes_len = self.attributes.encoded_len()?;
        let size: usize = 20 + attributes_len;
        if size > MAX_PACKET_SIZE {
            return Err(PacketParseError::InvalidLength(size));
        }
        let mut b = vec![0u8; size];
        b[0] = self.code as u8;
        b[1] = self.identifier;
        b[2..4].copy_from_slice(&(size as u16).to_be_bytes());
        b[4..20].copy_from_slice(&self.authenticator);
        self.attributes.encode_to(&mut b[20..]);
        Ok(b)
    }
    pub fn verify_request(&self, secret: &[u8]) -> bool {
        // The packet struct likely already stores the shared secret,
        // but for a robust verify method, it's best to use the secret passed in.
        if secret.is_empty() {
            return false;
        }

        match self.code {
            // Access-Request and Status-Server packets typically rely on the
            // Request Authenticator being a random seed for password/attribute encryption.
            // A simple implementation often assumes it's valid if the packet can be parsed.
            Code::AccessRequest | Code::StatusServer => true,

            // These request types MUST contain a valid Message-Authenticator.
            // The Message-Authenticator hash is calculated over the entire packet,
            // but with the primary Authenticator field (bytes 4-20) temporarily zeroed out.
            Code::AccountingRequest | Code::DisconnectRequest | Code::CoARequest => {
                // 1. Get the raw packet bytes.
                let packet_raw_result = self.encode_raw();
                if packet_raw_result.is_err() {
                    return false;
                }
                let mut packet_raw = packet_raw_result.unwrap();

                // 2. Zero out the primary Authenticator field (bytes 4-20) for the hash calculation.
                const NUL_AUTHENTICATOR: [u8; 16] = [0u8; 16];
                packet_raw[4..20].copy_from_slice(&NUL_AUTHENTICATOR);

                // 3. Start the MD5 hash calculation.
                let mut hasher = Md5::new();

                // Hash the entire zeroed packet.
                hasher.update(&packet_raw);

                // Hash the shared secret.
                hasher.update(secret);

                // 4. Calculate the final hash.
                let calculated_hash = hasher.finalize();

                // 5. Compare the calculated hash with the Authenticator received in the packet.
                // The calculated hash should match the value found in the packet's Message-Authenticator
                // attribute (Type 80). Since your code seems to be comparing against the *primary* // authenticator field (`self.authenticator`), we follow that logic.

                let calculated_bytes: [u8; 16] = calculated_hash.into();

                // The authenticator field in the Packet struct should hold the value received from the client.
                calculated_bytes == self.authenticator
            }

            _ => false,
        }
    }

    pub fn verify_response(&self, request_packet: &Packet, secret: &[u8]) -> bool {
        if secret.is_empty() {
            return false;
        }
        let response_raw = self.encode_raw();
        if response_raw.is_err() {
            return false;
        }
        let response_raw = response_raw.unwrap();
        if response_raw.len() < 20 {
            return false;
        }
        let mut hasher = Md5::new();
        hasher.update(&response_raw[0..4]);
        hasher.update(&request_packet.authenticator);
        hasher.update(&response_raw[20..]);
        hasher.update(secret);
        let calculated_hash = hasher.finalize();
        let calculated_bytes: [u8; 16] = calculated_hash.into();
        calculated_bytes == self.authenticator
    }

    pub fn get_attribute(&self, key: u8) -> Option<&AttributeValue> {
        self.attributes.get(key)
    }

    pub fn set_attribute(&mut self, key: u8, value: AttributeValue) {
        self.attributes.set(key, value);
    }
    pub fn get_vsa_attribute(&self, vendor_id: u32, vendor_type: u8) -> Option<&[u8]> {
        self.attributes.get_vsa_attribute(vendor_id, vendor_type)
    }
    pub fn set_vsa_attribute(&mut self, vendor_id: u32, vendor_type: u8, value: AttributeValue) {
        self.attributes
            .set_vsa_attribute(vendor_id, vendor_type, value);
    }
 pub fn create_response(&self, code: Code) -> Packet {
        Packet {
            code,
            identifier: self.identifier, 
            authenticator: self.authenticator,
            attributes: Attributes::new(),
            secret: self.secret.clone(),
        }
    }
}

impl From<AttributeParseError> for PacketParseError {
    fn from(err: AttributeParseError) -> Self {
        PacketParseError::AttributeError(err)
    }
}
