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
        unimplemented!()
    }
    pub fn encoded_len(&self) -> Result<usize, AttributeParseError> {
        unimplemented!()
    }
}
