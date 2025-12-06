pub type AttributeType = u8;
pub type AttributeValue = Vec<u8>;

pub struct Avp {
    pub attribute_type: AttributeType,
    pub value: AttributeValue,
}

pub struct Attributes(pub Vec<Avp>);

#[derive(Debug, thiserror::Error)]
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
}
