use md5::{Digest, Md5};
use rand::Rng;
use std::io::Cursor;
use thiserror::Error;

use crate::{
    Code,
    attribute::{self, AttributeParseError, Attributes},
};

const MAX_PACKET_SIZE: usize = 4096;
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

    pub fn parse_packet<'a>(b: &'a [u8], secret: &'a [u8]) -> Result<Packet, PacketParseError> {
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
        Ok(Packet {
            code,
            identifier: b[1],
            authenticator,
            attributes: attrs, // Attribute parsing can be added here
            secret: secret.to_vec(),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, PacketParseError> {
        let mut b = self.encode_raw()?;
        let code = self.code;

        match code {
            Code::AccessRequest | Code::StatusServer => Ok(b),
            Code::AccessAccept
            | Code::AccessReject
            | Code::AccessChallenge
            | Code::AccountingRequest
            | Code::AccountingResponse
            | Code::DisconnectRequest
            | Code::DisconnectAck
            | Code::DisconnectNak
            | Code::CoARequest
            | Code::CoAACK
            | Code::CoANAK => {
                let mut hasher = Md5::new();
                hasher.update(&b[0..4]);
                match code {
                    Code::AccountingRequest | Code::DisconnectRequest | Code::CoARequest => {
                        const NUL_AUTHENTICATOR: [u8; 16] = [0u8; 16];
                        hasher.update(NUL_AUTHENTICATOR);
                    }
                    _ => {
                        hasher.update(self.authenticator);
                    }
                }
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
        self.attributes.encode_to(&mut b[20..]);
        Ok(b)
    }
}
impl From<AttributeParseError> for PacketParseError {
    fn from(err: AttributeParseError) -> Self {
        PacketParseError::AttributeError(err)
    }
}
