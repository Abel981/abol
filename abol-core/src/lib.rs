pub mod attribute;
pub mod packet;
use crate::packet::{Packet, PacketParseError};
use core::fmt;
use std::{
    convert::TryFrom,
    fmt::{Display, Formatter},
    net::IpAddr,
};
/// Represents a RADIUS request received by the server.
///
/// Contains metadata about the client connection and the parsed RADIUS packet.
pub struct Request {
    /// Local socket address (IP:port) of the server that received the request.
    pub local_addr: String,
    /// Remote socket address (IP:port) of the client sending the request.
    pub remote_addr: String,
    /// Parsed RADIUS packet for this request.
    pub packet: Packet,
}
/// Represents a RADIUS response to be sent back to the client.
///
/// Wraps a `Packet` that will be transmitted as the response.
pub struct Response {
    /// RADIUS packet that will be sent as a response.
    pub packet: Packet,
}

/// RADIUS packet codes as defined in [RFC 2865](https://datatracker.ietf.org/doc/html/rfc2865).
///
/// Each variant corresponds to the `Code` field in the RADIUS header, indicating
/// the type of request or response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    /// Access-Request (1): Used by a client to request authentication.
    AccessRequest = 1,
    /// Access-Accept (2): Server response granting access.
    AccessAccept = 2,
    /// Access-Reject (3): Server response denying access.
    AccessReject = 3,
    /// Accounting-Request (4): Used by a client to send accounting data.
    AccountingRequest = 4,
    /// Accounting-Response (5): Server acknowledgment of an Accounting-Request.
    AccountingResponse = 5,
    /// Access-Challenge (11): Server requests additional information.
    AccessChallenge = 11,
    /// Status-Server (12): Experimental code for server status.
    StatusServer = 12,
    /// Status-Client (13): Experimental code for client status.
    StatusClient = 13,
    /// Disconnect-Request (40): Used in CoA to terminate a session.
    DisconnectRequest = 40,
    /// Disconnect-ACK (41): Acknowledgment of Disconnect-Request.
    DisconnectAck = 41,
    /// Disconnect-NAK (42): Negative acknowledgment of Disconnect-Request.
    DisconnectNak = 42,
    /// CoA-Request (43): Change-of-Authorization request.
    CoARequest = 43,
    /// CoA-ACK (44): Acknowledgment of CoA request.
    CoAACK = 44,
    /// CoA-NAK (45): Negative acknowledgment of CoA request.
    CoANAK = 45,
    /// Reserved (255): Reserved/experimental codes not standardized.
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
/// Represents an IP network prefix using Classless Inter-Domain Routing (CIDR) notation.
///
/// This struct is used to define a range of IP addresses (a subnet) by combining
/// a base IP address with a routing prefix length.
///
/// # Example
/// ```rust
/// # use std::error::Error;
/// # use std::net::IpAddr;
/// # use abol_core::Cidr;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// let network = Cidr {
///     ip: "192.168.1.0".parse()?,
///     prefix: 24,
/// };
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cidr {
    /// The base IP address of the network.
    pub ip: IpAddr,

    /// The routing prefix length (the number of leading bits in the subnet mask).
    ///
    /// For IPv4, this should be in the range 0..=32.
    /// For IPv6, this should be in the range 0..=128.
    pub prefix: u8,
}

impl Cidr {
    pub fn contains(&self, other: &IpAddr) -> bool {
        match (self.ip, other) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0);
                u32::from(net) & mask == u32::from(*ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix as u32).unwrap_or(0);
                u128::from(net) & mask == u128::from(*ip) & mask
            }
            _ => false,
        }
    }
}
