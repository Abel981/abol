use md5::{Digest, Md5};
use rand::Rng;
use rand::RngCore;
use thiserror::Error;

use crate::{
    Code,
    attribute::{
        self, AttributeParseError, AttributeValue, Attributes, FromRadiusAttribute,
        ToRadiusAttribute,
    },
};

pub const MAX_PACKET_SIZE: usize = 4096;
#[derive(Debug, Clone)]
pub struct Packet {
    pub code: Code,
    pub identifier: u8,
    pub authenticator: [u8; 16],
    pub attributes: Attributes,
    pub secret: Vec<u8>,
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
    /// Creates a new RADIUS packet with a cryptographically random authenticator.
    ///
    /// This constructor initializes a [`Packet`] with:
    /// - A randomly generated 16-byte authenticator
    /// - A randomly chosen packet identifier
    /// - An empty attribute set
    /// - The shared secret used for request/response authentication
    ///
    /// The authenticator is generated using the thread-local random number
    /// generator and is suitable for use in authentication and accounting
    /// packets as defined by RFC 2865.
    ///
    /// # Parameters
    ///
    /// - `code`: The RADIUS packet code (e.g. `AccessRequest`, `AccessAccept`)
    /// - `secret`: The shared secret between the client and the RADIUS server
    ///
    /// # Security
    ///
    /// The provided `secret` is copied into the packet and later used for
    /// authenticator verification and password obfuscation. Callers should
    /// take care to protect this value and avoid reusing it across unrelated
    /// security domains.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use abol::core::{Packet, Code};
    ///
    /// let packet = Packet::new(Code::AccessRequest, "shared-secret");
    /// assert_eq!(packet.attributes.len(), 0);
    /// ```
    ///
    /// # Notes
    ///
    /// This function does not perform any validation on the secret length.
    /// Validation is deferred to packet encoding and verification stages.
    pub fn new(code: Code, secret: impl Into<Vec<u8>>) -> Self {
        let mut rng = rand::rng();
        let mut authenticator = [0u8; 16];
        rng.fill_bytes(&mut authenticator);

        Packet {
            code,
            identifier: rng.random::<u8>(),
            authenticator,
            attributes: Attributes(Vec::new()),
            secret: secret.into(),
        }
    }

    pub fn parse_packet<'a>(b: &'a [u8], secret: &'a [u8]) -> Result<Self, PacketParseError> {
        if b.len() < 20 {
            return Err(PacketParseError::TooShortHeader);
        }

        if b.len() > MAX_PACKET_SIZE {
            return Err(PacketParseError::InvalidLength(b.len()));
        }

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
            (plaintext.len() + 15) / 16
        };
        let mut enc = Vec::with_capacity(chunks * 16);

        let mut hasher = Md5::new();
        hasher.update(&self.secret);
        hasher.update(&self.authenticator);
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
        if encrypted.is_empty() || encrypted.len() % 16 != 0 || self.secret.is_empty() {
            return None;
        }

        let mut plaintext = Vec::with_capacity(encrypted.len());
        let mut last_round = self.authenticator.to_vec();

        for chunk in encrypted.chunks(16) {
            let mut hasher = Md5::new();
            hasher.update(&self.secret);
            hasher.update(&last_round);
            let b = hasher.finalize();
            for i in 0..16 {
                plaintext.push(chunk[i] ^ b[i]);
            }
            last_round = chunk.to_vec();
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
        while data.len() % 16 != 0 {
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
        if encrypted.len() < 18 || (encrypted.len() - 2) % 16 != 0 || self.secret.is_empty() {
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
                let decrypted = self.decrypt_user_password(raw)?;
                T::from_bytes(&decrypted)
            }
            69 => {
                // Tunnel-Password
                let raw = self.get_attribute(69)?;
                let decrypted = self.decrypt_tunnel_password(raw)?;
                T::from_bytes(&decrypted)
            }
            _ => self
                .get_attribute(type_code)
                .and_then(|raw| T::from_bytes(raw)),
        }
    }

    pub fn set_attribute_as<T: ToRadiusAttribute>(&mut self, type_code: u8, value: T) {
        match type_code {
            2 => {
                if let Some(encrypted) = self.encrypt_user_password(&value.to_bytes()) {
                    self.set_attribute(2, encrypted);
                }
            }
            69 => {
                if let Some(encrypted) = self.encrypt_tunnel_password(&value.to_bytes()) {
                    self.set_attribute(69, encrypted);
                }
            }
            _ => self.set_attribute(type_code, value.to_bytes()),
        }
    }

    pub fn get_vsa_attribute_as<T: FromRadiusAttribute>(&self, v_id: u32, v_type: u8) -> Option<T> {
        self.get_vsa_attribute(v_id, v_type)
            .and_then(|raw| T::from_bytes(raw))
    }

    pub fn set_vsa_attribute_as<T: ToRadiusAttribute>(&mut self, v_id: u32, v_type: u8, value: T) {
        self.set_vsa_attribute(v_id, v_type, value.to_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_new_with_various_types() {
        // Works with string literals
        let _p1 = Packet::new(Code::AccessRequest, "mysecret");

        // Works with byte slices
        let _p2 = Packet::new(Code::AccessRequest, b"mysecret" as &[u8]);

        // Works with owned Vectors (move, no allocation)
        let secret_vec = vec![1, 2, 3, 4];
        let _p3 = Packet::new(Code::AccessRequest, secret_vec);
    }

    #[test]
    fn parse_valid_packet() {
        let secret = b"shared-secret";

        // Minimal valid RADIUS packet (20 bytes, no attributes)
        let mut buf = vec![0u8; 20];
        buf[0] = Code::AccessRequest as u8; // Code
        buf[1] = 42; // Identifier
        buf[2..4].copy_from_slice(&(20u16.to_be_bytes())); // Length

        // Authenticator (16 bytes)
        for i in 4..20 {
            buf[i] = i as u8;
        }

        let packet = Packet::parse_packet(&buf, secret).expect("packet should parse");

        assert_eq!(packet.code, Code::AccessRequest);
        assert_eq!(packet.identifier, 42);
        assert_eq!(packet.authenticator, buf[4..20]);
        assert_eq!(packet.attributes, Attributes(Vec::new()));
        assert_eq!(packet.secret, secret);
    }

    #[test]
    fn parse_packet_too_short() {
        let secret = b"shared-secret";
        let buf = vec![0u8; 10]; // shorter than 20 bytes

        let err = Packet::parse_packet(&buf, secret).unwrap_err();

        assert_eq!(err, PacketParseError::TooShortHeader);
    }
    #[test]
    fn test_encode_access_request_preserves_authenticator() {
        let mut packet = Packet::new(Code::AccessRequest, "secret");
        let auth = [1u8; 16];
        packet.authenticator = auth;

        let encoded = packet.encode().unwrap();
        assert_eq!(&encoded[4..20], &auth);
    }
    #[test]
    fn test_verify_request_accounting_valid() {
        let secret = b"super-secret";
        let mut packet = Packet::new(Code::AccountingRequest, secret.to_vec());

        // encode() calculates the valid accounting authenticator
        let encoded_bytes = packet.encode().unwrap();

        // Parse it back to simulate receiving it
        let received = Packet::parse_packet(&encoded_bytes, secret).unwrap();

        assert!(received.verify_request(secret));
    }

    #[test]
    fn test_verify_request_accounting_invalid_secret() {
        let secret = b"real-secret";
        let wrong_secret = b"hacker-secret";
        let mut packet = Packet::new(Code::AccountingRequest, secret.to_vec());

        let encoded_bytes = packet.encode().unwrap();
        let received = Packet::parse_packet(&encoded_bytes, secret).unwrap();

        assert!(!received.verify_request(wrong_secret));
    }

    #[test]
    fn test_verify_request_accounting_tampered_data() {
        let secret = b"secret";
        let mut packet = Packet::new(Code::AccountingRequest, secret);
        let mut encoded_bytes = packet.encode().unwrap();

        // Tamper with the identifier after encoding
        encoded_bytes[1] ^= 0xFF;

        let received = Packet::parse_packet(&encoded_bytes, secret).unwrap();
        assert!(!received.verify_request(secret));
    }

    #[test]
    fn test_verify_request_access_request_always_true() {
        let secret = b"secret";
        let packet = Packet::new(Code::AccessRequest, secret);
        // Access-Request doesn't use the header authenticator for verification
        // (it uses it for password decryption instead)
        assert!(packet.verify_request(secret));
    }

    #[test]
    fn test_user_password_roundtrip() {
        let secret = b"shared-secret";
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
        let secret = b"shared-secret";
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
        // Verify salt is present (first 2 bytes) and length is correct
        assert_eq!(encrypted.len(), 2 + 32); // 2 bytes salt + 2 blocks of 16
        assert!(encrypted[0] >= 0x80, "Salt MSB must be set");
    }

    #[test]
    fn test_encrypt_user_password_blocks() {
        let secret = b"mysecret";
        let mut packet = Packet::new(Code::AccessRequest, secret);
        packet.authenticator = [0x11; 16]; // Fixed authenticator for deterministic test

        // 1. Short password (1 block)
        let pass1 = b"password";
        let enc1 = packet.encrypt_user_password(pass1).unwrap();
        assert_eq!(enc1.len(), 16);

        // 2. Long password (2 blocks)
        let pass2 = b"this-is-a-very-long-password-exceeding-16-bytes";
        let enc2 = packet.encrypt_user_password(pass2).unwrap();
        assert_eq!(enc2.len(), 48); // 48 is the next multiple of 16 for this length

        // 3. Round-trip logic check (manual decryption)
        let mut hasher = Md5::new();
        hasher.update(secret);
        hasher.update(&packet.authenticator);
        let b1 = hasher.finalize();

        let decrypted_p1 = enc1[0] ^ b1[0];
        assert_eq!(decrypted_p1, b'p');
    }
}
