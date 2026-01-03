use std::{net::{Ipv4Addr, Ipv6Addr}, time::{Duration, SystemTime, UNIX_EPOCH}};
pub type AttributeType = u8;
pub type AttributeValue = Vec<u8>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Avp {
    pub attribute_type: AttributeType,
    pub value: AttributeValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attributes(pub Vec<Avp>);
impl Attributes {
    pub fn new() -> Self {
        Attributes(Vec::new())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AttributeParseError {
    #[error("Buffer too short for attribute header")]
    ShortBuffer,
    #[error("Invalid attribute length: {0}")]
    InvalidLength(u8),
}

pub fn parse_attributes(mut b: &[u8]) -> Result<Attributes, AttributeParseError> {
    let mut attrs = Vec::new();
    while !b.is_empty() {
        if b.len() < 2 {
            return Err(AttributeParseError::ShortBuffer);
        }
        let attribute_type = b[0];
        let length = b[1] as usize;
        if length < 2 || length > b.len() {
            return Err(AttributeParseError::InvalidLength(b[1]));
        }
        let value = &b[2..length];
        let avp = Avp {
            attribute_type,
            value: value.to_vec(),
        };
        attrs.push(avp);
        b = &b[length..];
    }
    Ok(Attributes(attrs))
}

impl Attributes {
    pub fn add(&mut self, key: AttributeType, value: AttributeValue) {
        self.0.push(Avp {
            attribute_type: key,
            value,
        });
    }

    pub fn get(&self, key: AttributeType) -> Option<&AttributeValue> {
        self.0
            .iter()
            .find(|avp| avp.attribute_type == key)
            .map(|avp| &avp.value)
    }

    pub fn del(&mut self, key: AttributeType) {
        self.0.retain(|avp| avp.attribute_type != key);
    }

    pub fn set(&mut self, key: AttributeType, value: AttributeValue) {
        self.del(key);
        self.add(key, value);
    }
    pub fn encode_to(&self, buf: &mut [u8]) -> Result<(), AttributeParseError> {
        let mut offset: usize = 0;
        for attr in &self.0 {
            let value_len = attr.value.len();
            if value_len > 253 {
                return Err(AttributeParseError::InvalidLength((value_len + 2) as u8));
            }
            let avp_size = 2 + value_len;
            let next_offset = offset + avp_size;
            if next_offset > buf.len() {
                return Err(AttributeParseError::ShortBuffer);
            }
            let avp_slice = &mut buf[offset..next_offset];
            avp_slice[0] = attr.attribute_type;
            avp_slice[1] = avp_size as u8;
            avp_slice[2..].copy_from_slice(&attr.value);
            offset = next_offset;
        }
        Ok(())
    }

    pub fn encoded_len(&self) -> Result<usize, AttributeParseError> {
        let mut total_len = 0;
        for attr in &self.0 {
            let value_len = attr.value.len();
            if value_len > 253 {
                return Err(AttributeParseError::InvalidLength((value_len + 2) as u8));
            }
            total_len += 2 + value_len;
        }
        Ok(total_len)
    }

    pub fn get_vsa_attribute(&self, vendor_id: u32, vendor_type: u8) -> Option<&[u8]> {
        for avp in &self.0 {
            if avp.attribute_type == 26 && avp.value.len() >= 6 {
                let v_id =
                    u32::from_be_bytes([avp.value[0], avp.value[1], avp.value[2], avp.value[3]]);
                let v_type = avp.value[4];

                if v_id == vendor_id && v_type == vendor_type {
                    return Some(&avp.value[6..]);
                }
            }
        }
        None
    }
    pub fn set_vsa_attribute(&mut self, vendor_id: u32, vendor_type: u8, value: AttributeValue) {
        self.0.retain(|avp| {
            if avp.attribute_type != 26 || avp.value.len() < 6 {
                return true;
            }
            let v_id = u32::from_be_bytes([avp.value[0], avp.value[1], avp.value[2], avp.value[3]]);
            let v_type = avp.value[4];
            !(v_id == vendor_id && v_type == vendor_type)
        });

        let mut vsa_value = Vec::with_capacity(6 + value.len());
        vsa_value.extend_from_slice(&vendor_id.to_be_bytes());
        vsa_value.push(vendor_type);
        vsa_value.push((2 + value.len()) as u8);
        vsa_value.extend_from_slice(&value);
        self.0.push(Avp {
            attribute_type: 26,
            value: vsa_value,
        });
    }

    
}
pub trait FromRadiusAttribute: Sized {
    fn from_bytes(bytes: &[u8]) -> Option<Self>;
}

pub trait ToRadiusAttribute {
    fn to_bytes(&self) -> Vec<u8>;
}

impl FromRadiusAttribute for u16 {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let b: [u8; 2] = bytes.try_into().ok()?;
        Some(u16::from_be_bytes(b))
    }
}

impl ToRadiusAttribute for u16 {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl FromRadiusAttribute for u32 {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let b: [u8; 4] = bytes.try_into().ok()?;
        Some(u32::from_be_bytes(b))
    }
}

impl ToRadiusAttribute for u32 {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl FromRadiusAttribute for u64 {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let b: [u8; 8] = bytes.try_into().ok()?;
        Some(u64::from_be_bytes(b))
    }
}

impl ToRadiusAttribute for u64 {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl FromRadiusAttribute for Ipv4Addr {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let b: [u8; 4] = bytes.try_into().ok()?;
        Some(Ipv4Addr::from(b))
    }
}

impl ToRadiusAttribute for Ipv4Addr {
    fn to_bytes(&self) -> Vec<u8> {
        self.octets().to_vec()
    }
}

impl FromRadiusAttribute for Ipv6Addr {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let b: [u8; 16] = bytes.try_into().ok()?;
        Some(Ipv6Addr::from(b))
    }
}

impl ToRadiusAttribute for Ipv6Addr {
    fn to_bytes(&self) -> Vec<u8> {
        self.octets().to_vec()
    }
}

impl FromRadiusAttribute for String {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        String::from_utf8(bytes.to_vec()).ok()
    }
}

impl ToRadiusAttribute for String {
    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl FromRadiusAttribute for Vec<u8> {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Some(bytes.to_vec())
    }
}

impl ToRadiusAttribute for Vec<u8> {
    fn to_bytes(&self) -> Vec<u8> {
        self.clone()
    }
}

impl FromRadiusAttribute for SystemTime {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let secs = u32::from_bytes(bytes)?;
        Some(UNIX_EPOCH + Duration::from_secs(secs as u64))
    }
}

impl ToRadiusAttribute for SystemTime {
    fn to_bytes(&self) -> Vec<u8> {
        let duration = self.duration_since(UNIX_EPOCH).unwrap_or_default();
        (duration.as_secs() as u32).to_bytes()
    }
}

/// Helper for Type-Length-Value (TLV) attributes
pub struct Tlv {
    pub tlv_type: u8,
    pub value: Vec<u8>,
}

impl FromRadiusAttribute for Tlv {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 || bytes[1] as usize != bytes.len() {
            return None;
        }
        Some(Tlv {
            tlv_type: bytes[0],
            value: bytes[2..].to_vec(),
        })
    }
}

impl ToRadiusAttribute for Tlv {
    fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(2 + self.value.len());
        v.push(self.tlv_type);
        v.push((2 + self.value.len()) as u8);
        v.extend_from_slice(&self.value);
        v
    }
}

