pub mod attribute;
pub mod packet;
use crate::packet::{Packet, PacketParseError};
use core::fmt;
use std::{
    convert::TryFrom,
    error::Error,
    fmt::{Display, Formatter},
};
pub type HandlerResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
pub struct Request {
    pub local_addr: String,
    pub remote_addr: String,
    pub packet: Packet,
}
pub struct Response {
    pub packet: Packet,
}

impl Response {
    pub fn new(packet: Packet) -> Self {
        Self { packet }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    AccessRequest = 1,
    AccessAccept = 2,
    AccessReject = 3,
    AccountingRequest = 4,
    AccountingResponse = 5,
    AccessChallenge = 11,
    /// Experimental Code from RFC 2865
    StatusServer = 12,
    StatusClient = 13,
    DisconnectRequest = 40,
    DisconnectAck = 41,
    DisconnectNak = 42,
    CoARequest = 43,
    CoAACK = 44,
    CoANAK = 45,
    /// Experimental Codes from RFC 2865
    Reserved = 255,
}
impl Display for Code {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let text = match self {
            Code::AccessRequest => "Access-Request",
            Code::AccessAccept => "Access-Accept",
            Code::AccessReject => "Access-Reject",
            Code::AccountingRequest => "Accounting-Request",
            Code::AccountingResponse => "Accounting-Response",
            Code::AccessChallenge => "Access-Challenge",
            Code::StatusServer => "Status-Server",
            Code::StatusClient => "Status-Client",
            Code::DisconnectRequest => "Disconnect-Request",
            Code::DisconnectAck => "Disconnect-ACK",
            Code::DisconnectNak => "Disconnect-NAK",
            Code::CoARequest => "CoA-Request",
            Code::CoAACK => "CoA-ACK",
            Code::CoANAK => "CoA-NAK",
            Code::Reserved => "Reserved",
        };

        write!(f, "{}", text)
    }
}

impl TryFrom<u8> for Code {
    type Error = PacketParseError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Code::AccessRequest),
            2 => Ok(Code::AccessAccept),
            3 => Ok(Code::AccessReject),
            4 => Ok(Code::AccountingRequest),
            5 => Ok(Code::AccountingResponse),
            11 => Ok(Code::AccessChallenge),
            12 => Ok(Code::StatusServer),
            13 => Ok(Code::StatusClient),
            40 => Ok(Code::DisconnectRequest),
            41 => Ok(Code::DisconnectAck),
            42 => Ok(Code::DisconnectNak),
            43 => Ok(Code::CoARequest),
            44 => Ok(Code::CoAACK),
            45 => Ok(Code::CoANAK),
            255 => Ok(Code::Reserved),
            _ => Err(PacketParseError::InvalidLength(value as usize)),
        }
    }
}

