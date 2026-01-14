#![allow(dead_code)]
use bytes::Bytes;
use md5::{Digest, Md5};
use rand::Rng;
use rand::RngCore;
use std::sync::Arc;
use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    Code,
    attribute::{
        self, AttributeParseError, AttributeValue, Attributes, FromRadiusAttribute,
        ToRadiusAttribute,
    },
};

pub const MAX_PACKET_SIZE: usize = 4096;
/// Represents a parsed or ready-to-be-sent RADIUS packet.
///
/// This struct acts as the primary container for RADIUS data, including the fixed
/// header fields and the variable-length attributes.
#[derive(Debug, Clone)]
pub struct Packet {
    /// The RADIUS packet type (e.g., Access-Request, Access-Accept).
    pub code: Code,

    /// A sequence number used to match requests with responses.
    /// The client should increment this for each new request.
    pub identifier: u8,

    /// A 16-octet value used to authenticate the reply from the RADIUS server
    /// and to hide passwords.
    pub authenticator: [u8; 16],

    /// A collection of RADIUS attributes containing the data for the request or response.
    pub attributes: Attributes,

    /// The shared secret used for packet authentication and attribute encryption.
    pub secret: Arc<[u8]>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PacketParseError {
    #[error("Packet not at least 20 bytes long")]
    TooShortHeader,
    #[error("unknown packet code")]
    UnknownPacketCode,
    #[error("Invalid packet length: {0}")]
    InvalidLength(usize),
    #[error("Attribute parsing failed: {0}")]
    AttributeError(AttributeParseError),
}
impl Packet {
    fn new(code: Code, secret: Arc<[u8]>) -> Self {
        let mut rng = rand::rng();
        let mut authenticator = [0u8; 16];
        rng.fill_bytes(&mut authenticator);

        Packet {
            code,
            identifier: rng.random::<u8>(),
            authenticator,
            attributes: Attributes::default(),
            secret,
        }
    }

    pub fn parse_packet(b: Bytes, secret: Arc<[u8]>) -> Result<Self, PacketParseError> {
        if b.len() < 20 {
            return Err(PacketParseError::TooShortHeader);
        }

        if b.len() > MAX_PACKET_SIZE {
            return Err(PacketParseError::InvalidLength(b.len()));
        }

        let length = u16::from_be_bytes([b[2], b[3]]) as usize;

        if !(20..=MAX_PACKET_SIZE).contains(&length) {
            return Err(PacketParseError::InvalidLength(length));
        }

        let code = Code::try_from(b[0])?;
        let identifier = b[1];

        let mut authenticator = [0u8; 16];
        authenticator.copy_from_slice(&b[4..20]);

        let attribute_data = b.slice(20..length);
        let attrs = attribute::parse_attributes(attribute_data)?;

        Ok(Self {
            code,
            identifier,
            authenticator,
            attributes: attrs,
            secret,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, PacketParseError> {
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

                hasher.update(&b[0..4]);

                hasher.update(&b[4..20]);

                hasher.update(&b[20..]);

                hasher.update(&self.secret);

                let hash_result = hasher.finalize();
                b[4..20].copy_from_slice(&hash_result);

                Ok(b)
            }
            Code::AccountingRequest | Code::DisconnectRequest | Code::CoARequest => {
                let mut hasher = Md5::new();
                hasher.update(&b[0..4]);

                // Zero out the Authenticator field for the hash calculation
                const NUL_AUTHENTICATOR: [u8; 16] = [0u8; 16];
                hasher.update(NUL_AUTHENTICATOR);

                hasher.update(&b[20..]);
                hasher.update(&self.secret);

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
        self.attributes
            .encode_to(&mut b[20..])
            .map_err(PacketParseError::AttributeError)?;
        Ok(b)
    }
    pub fn verify_request(&self) -> bool {
        if self.secret.is_empty() {
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
                let packet_raw_result = self.encode_raw();
                if packet_raw_result.is_err() {
                    return false;
                }
                let mut packet_raw = packet_raw_result.unwrap();

                const NUL_AUTHENTICATOR: [u8; 16] = [0u8; 16];
                packet_raw[4..20].copy_from_slice(&NUL_AUTHENTICATOR);

                let mut hasher = Md5::new();

                // Hash the entire zeroed packet.
                hasher.update(&packet_raw);

                // Hash the shared secret.
                hasher.update(&*self.secret);

                let calculated_hash = hasher.finalize();

                let calculated_bytes: [u8; 16] = calculated_hash.into();

                // The authenticator field in the Packet struct should hold the value received from the client.
                calculated_bytes == self.authenticator
            }

            _ => false,
        }
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
    /// Encrypts a plaintext password according to RFC 2865 (User-Password)
    pub fn encrypt_user_password(&self, plaintext: &[u8]) -> Option<Vec<u8>> {
        if plaintext.len() > 128 || self.secret.is_empty() {
            return None;
        }

        let chunks = if plaintext.is_empty() {
            1
        } else {
            plaintext.len().div_ceil(16)
        };
        let mut enc = Vec::with_capacity(chunks * 16);

        let mut hasher = Md5::new();
        hasher.update(&self.secret);
        hasher.update(self.authenticator);
        let mut b = hasher.finalize();

        // First 16-byte block
        for i in 0..16 {
            let p_byte = if i < plaintext.len() { plaintext[i] } else { 0 };
            enc.push(p_byte ^ b[i]);
        }

        // Subsequent blocks
        for i in 1..chunks {
            hasher = Md5::new();
            hasher.update(&self.secret);
            hasher.update(&enc[(i - 1) * 16..i * 16]);
            b = hasher.finalize();

            for j in 0..16 {
                let offset = i * 16 + j;
                let p_byte = if offset < plaintext.len() {
                    plaintext[offset]
                } else {
                    0
                };
                enc.push(p_byte ^ b[j]);
            }
        }
        Some(enc)
    }

    /// Decrypts a User-Password attribute according to RFC 2865
    pub fn decrypt_user_password(&self, encrypted: &[u8]) -> Option<Vec<u8>> {
        if encrypted.is_empty() || !encrypted.len().is_multiple_of(16) || self.secret.is_empty() {
            return None;
        }

        let mut plaintext = Vec::with_capacity(encrypted.len());
        let mut last_round = [0u8; 16];
        last_round.copy_from_slice(&self.authenticator);

        for chunk in encrypted.chunks(16) {
            let mut hasher = Md5::new();
            hasher.update(&*self.secret);
            hasher.update(last_round);
            let b = hasher.finalize();
            for i in 0..16 {
                plaintext.push(chunk[i] ^ b[i]);
            }
            last_round.copy_from_slice(chunk);
        }
        let mut end = plaintext.len();
        while end > 0 && plaintext[end - 1] == 0 {
            end -= 1;
        }
        Some(plaintext[..end].to_vec())
    }

    /// Encrypts Tunnel-Password according to RFC 2868
    pub fn encrypt_tunnel_password(&self, plaintext: &[u8]) -> Option<Vec<u8>> {
        if self.secret.is_empty() {
            return None;
        }

        let mut salt = [0u8; 2];
        rand::rng().fill_bytes(&mut salt);
        salt[0] |= 0x80;

        let mut data = vec![plaintext.len() as u8];
        data.extend_from_slice(plaintext);
        while !data.len().is_multiple_of(16) {
            data.push(0);
        }

        let mut result = salt.to_vec();
        let mut last_round = Vec::with_capacity(16 + 2);
        last_round.extend_from_slice(&self.authenticator);
        last_round.extend_from_slice(&salt);

        for chunk in data.chunks(16) {
            let mut hasher = Md5::new();
            hasher.update(&self.secret);
            hasher.update(&last_round);
            let b = hasher.finalize();

            let mut encrypted_chunk = [0u8; 16];
            for i in 0..16 {
                encrypted_chunk[i] = chunk[i] ^ b[i];
            }
            result.extend_from_slice(&encrypted_chunk);
            last_round = encrypted_chunk.to_vec();
        }
        Some(result)
    }

    /// Decrypts Tunnel-Password according to RFC 2868
    pub fn decrypt_tunnel_password(&self, encrypted: &[u8]) -> Option<Vec<u8>> {
        if encrypted.len() < 18
            || !(encrypted.len() - 2).is_multiple_of(16)
            || self.secret.is_empty()
        {
            return None;
        }

        let salt = &encrypted[0..2];
        let ciphertext = &encrypted[2..];
        let mut plaintext = Vec::with_capacity(ciphertext.len());

        let mut last_round = Vec::with_capacity(16 + 2);
        last_round.extend_from_slice(&self.authenticator);
        last_round.extend_from_slice(salt);

        for chunk in ciphertext.chunks(16) {
            let mut hasher = Md5::new();
            hasher.update(&self.secret);
            hasher.update(&last_round);
            let b = hasher.finalize();
            for i in 0..16 {
                plaintext.push(chunk[i] ^ b[i]);
            }
            last_round = chunk.to_vec();
        }

        let len = plaintext[0] as usize;
        if len > plaintext.len() - 1 {
            return None;
        }
        Some(plaintext[1..1 + len].to_vec())
    }

    pub fn get_attribute_as<T: FromRadiusAttribute>(&self, type_code: u8) -> Option<T> {
        match type_code {
            2 => {
                // User-Password
                let raw = self.get_attribute(2)?;
                let mut decrypted = self.decrypt_user_password(raw)?;
                let result = T::from_bytes(&decrypted);
                decrypted.zeroize();
                result
            }
            69 => {
                // Tunnel-Password
                let raw = self.get_attribute(69)?;
                let mut decrypted = self.decrypt_tunnel_password(raw)?;
                let result = T::from_bytes(&decrypted);
                decrypted.zeroize();
                result
            }
            _ => self
                .get_attribute(type_code)
                .and_then(|raw| T::from_bytes(raw)),
        }
    }

    pub fn set_attribute_as<T: ToRadiusAttribute>(&mut self, type_code: u8, value: T) {
        match type_code {
            2 => {
                if let Some(encrypted_vec) = self.encrypt_user_password(&value.to_bytes()) {
                    let encrypted_bytes = Bytes::from(encrypted_vec);
                    self.set_attribute(2, encrypted_bytes);
                }
            }
            69 => {
                if let Some(encrypted_vec) = self.encrypt_tunnel_password(&value.to_bytes()) {
                    // Convert Vec<u8> to Bytes
                    let encrypted_bytes = Bytes::from(encrypted_vec);
                    self.set_attribute(69, encrypted_bytes);
                }
            }
            _ => {
                // Convert the standard attribute bytes to Bytes
                let attr_bytes = Bytes::from(value.to_bytes());
                self.set_attribute(type_code, attr_bytes);
            }
        }
    }

    pub fn get_vsa_attribute_as<T: FromRadiusAttribute>(&self, v_id: u32, v_type: u8) -> Option<T> {
        self.get_vsa_attribute(v_id, v_type)
            .and_then(|raw| T::from_bytes(raw))
    }

    pub fn set_vsa_attribute_as<T: ToRadiusAttribute>(&mut self, v_id: u32, v_type: u8, value: T) {
        let raw_bytes = value.to_bytes();

        let value_bytes = Bytes::from(raw_bytes);

        self.set_vsa_attribute(v_id, v_type, value_bytes);
    }

    pub fn create_response(&self, code: Code) -> Packet {
        Packet {
            code,
            identifier: self.identifier,
            authenticator: self.authenticator,
            attributes: Attributes::default(),
            secret: self.secret.clone(),
        }
    }
}

impl From<AttributeParseError> for PacketParseError {
    fn from(err: AttributeParseError) -> Self {
        PacketParseError::AttributeError(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn parse_packet_too_short() {
        let secret = Arc::from(&b"shared-secret"[..]);
        // Convert Vec to Bytes
        let buf = Bytes::from(vec![0u8; 10]);

        let err = Packet::parse_packet(buf, secret).unwrap_err();
        assert_eq!(err, PacketParseError::TooShortHeader);
    }

    #[test]
    fn test_encode_access_request_preserves_authenticator() {
        let mut packet = Packet::new(Code::AccessRequest, Arc::from(&b"secret"[..]));
        let auth = [1u8; 16];
        packet.authenticator = auth;

        let encoded = packet.encode().unwrap();
        // encoded is likely Bytes or Vec<u8> depending on your encode() return type
        assert_eq!(&encoded[4..20], &auth);
    }

    #[test]
    fn test_verify_request_accounting_valid() {
        let secret = Arc::from(&b"super-secret"[..]);
        let packet = Packet::new(Code::AccountingRequest, Arc::clone(&secret));

        // encode() should return something that can become Bytes
        let encoded_bytes = Bytes::from(packet.encode().unwrap());

        // Parse it back - the received packet will own a slice of encoded_bytes
        let received = Packet::parse_packet(encoded_bytes, Arc::clone(&secret)).unwrap();

        assert!(received.verify_request());
    }

    #[test]
    fn test_verify_request_accounting_invalid_secret() {
        let secret = Arc::from("real-secret".as_bytes());
        let wrong_secret = Arc::from("hacker-secret".as_bytes());

        let packet = Packet::new(Code::AccountingRequest, Arc::clone(&secret));
        let encoded_bytes = Bytes::from(packet.encode().unwrap());

        // Receiver uses the wrong secret for parsing/verification
        let received = Packet::parse_packet(encoded_bytes, wrong_secret).unwrap();

        assert!(!received.verify_request());
    }

    #[test]
    fn test_verify_request_accounting_tampered_data() {
        let secret = Arc::from(&b"secret"[..]);
        let packet_to_send = Packet::new(Code::AccountingRequest, Arc::clone(&secret));

        // We need a mutable version to tamper with it
        let mut encoded_vec = packet_to_send.encode().unwrap();

        // Tamper with the identifier (index 1)
        encoded_vec[1] ^= 0xFF;

        let received = Packet::parse_packet(Bytes::from(encoded_vec), secret).unwrap();
        assert!(!received.verify_request());
    }

    #[test]
    fn test_verify_request_access_request_always_true() {
        let secret = Arc::from(&b"secret"[..]);
        let packet = Packet::new(Code::AccessRequest, secret);
        assert!(packet.verify_request());
    }

    #[test]
    fn test_user_password_roundtrip() {
        let secret = Arc::from(&b"shared-secret"[..]);
        let mut packet = Packet::new(Code::AccessRequest, secret);
        packet.authenticator = [0x42; 16];

        let original = b"very-secure-password-123";
        let encrypted = packet
            .encrypt_user_password(original)
            .expect("Encryption failed");
        let decrypted = packet
            .decrypt_user_password(&encrypted)
            .expect("Decryption failed");

        assert_eq!(original.to_vec(), decrypted);
    }

    #[test]
    fn test_tunnel_password_roundtrip() {
        let secret = Arc::from(&b"shared-secret"[..]);
        let mut packet = Packet::new(Code::AccessRequest, secret);
        packet.authenticator = [0x77; 16];

        let original = b"tunnel-secret-password";
        let encrypted = packet
            .encrypt_tunnel_password(original)
            .expect("Tunnel encryption failed");
        let decrypted = packet
            .decrypt_tunnel_password(&encrypted)
            .expect("Tunnel decryption failed");

        assert_eq!(original.to_vec(), decrypted);
        assert_eq!(encrypted.len(), 2 + 32);
        assert!(encrypted[0] >= 0x80, "Salt MSB must be set");
    }

    #[test]
    fn test_encrypt_user_password_blocks() {
        let secret = Arc::from(&b"mysecret"[..]);
        let mut packet = Packet::new(Code::AccessRequest, Arc::clone(&secret));
        packet.authenticator = [0x11; 16];

        let pass1 = b"password";
        let enc1 = packet.encrypt_user_password(pass1).unwrap();
        assert_eq!(enc1.len(), 16);

        let pass2 = b"this-is-a-very-long-password-exceeding-16-bytes";
        let enc2 = packet.encrypt_user_password(pass2).unwrap();
        assert_eq!(enc2.len(), 48);

        // Manual check of first block
        let mut hasher = Md5::new();
        hasher.update(&*secret); // Deref Arc to slice for MD5
        hasher.update(&packet.authenticator);
        let b1 = hasher.finalize();

        let decrypted_p1 = enc1[0] ^ b1[0];
        assert_eq!(decrypted_p1, b'p');
    }
}
