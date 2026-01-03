use std::fmt;
use thiserror::Error;

#[derive(Default, Clone)]
pub struct Dictionary {
    pub attributes: Vec<DictionaryAttribute>,
    pub values: Vec<DictionaryValue>,
    pub vendors: Vec<DictionaryVendor>,
}
impl Dictionary {
    /// Merges another dictionary into this one.
    /// Returns a new Dictionary if successful, or an Error if conflicts are found.
    pub fn merge(d1: &Dictionary, d2: &Dictionary) -> Result<Dictionary, DictionaryError> {
        // 1. Validate top-level attribute conflicts
        for attr in &d2.attributes {
            if d1.attributes.iter().any(|a| a.name == attr.name) {
                return Err(DictionaryError::Conflict(format!(
                    "duplicate attribute name: {}",
                    attr.name
                )));
            }
            if d1.attributes.iter().any(|a| a.oid == attr.oid) {
                return Err(DictionaryError::Conflict(format!(
                    "duplicate attribute OID: {}",
                    attr.oid
                )));
            }
        }

        // 2. Validate Vendor conflicts
        for vendor in &d2.vendors {
            let existing_by_name = d1.vendors.iter().find(|v| v.name == vendor.name);
            let existing_by_code = d1.vendors.iter().find(|v| v.code == vendor.code);

            // If name exists but code is different, or code exists but name is different
            if existing_by_name != existing_by_code {
                return Err(DictionaryError::Conflict(format!(
                    "conflicting vendor definition: {} ({})",
                    vendor.name, vendor.code
                )));
            }

            // If the vendor already exists, check for attribute collisions within that vendor
            if let Some(existing) = existing_by_name {
                for attr in &vendor.attributes {
                    if existing.attributes.iter().any(|a| a.name == attr.name) {
                        return Err(DictionaryError::Conflict(format!(
                            "duplicate vendor attribute name: {}",
                            attr.name
                        )));
                    }
                    if existing.attributes.iter().any(|a| a.oid == attr.oid) {
                        return Err(DictionaryError::Conflict(format!(
                            "duplicate vendor attribute OID: {}",
                            attr.oid
                        )));
                    }
                }
            }
        }

        // 3. Perform the merge
        let mut new_dict = d1.clone();

        // Append top-level attributes and values
        new_dict.attributes.extend(d2.attributes.clone());
        new_dict.values.extend(d2.values.clone());

        // Merge vendors
        for v2 in &d2.vendors {
            if let Some(v1) = new_dict.vendors.iter_mut().find(|v| v.code == v2.code) {
                // Vendor exists: merge its attributes and values
                v1.attributes.extend(v2.attributes.clone());
                v1.values.extend(v2.values.clone());
            } else {
                new_dict.vendors.push(v2.clone());
            }
        }

        Ok(new_dict)
    }
}
#[derive(Error, Debug)]
pub enum DictionaryError {
    #[error("Dictionary conflict: {0}")]
    Conflict(String),
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AttributeType {
    String,
    Integer,
    IpAddr,
    Octets,
    Date,
    Vsa,
    Ether,
    ABinary,
    Byte,
    Short,
    Signed,
    Tlv,
    Ipv4Prefix,
    Ifid,
    Ipv6Addr,
    Ipv6Prefix,
    InterfaceId,
    //todo check unknown type and add all attributes
    Unknown(String),
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DictionaryAttribute {
    pub name: String,
    pub oid: Oid,
    pub attr_type: AttributeType,
    pub size: SizeFlag,
    pub encrypt: Option<u8>,
    pub has_tag: Option<bool>,
    pub concat: Option<bool>,
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Oid {
    pub vendor: Option<u32>,
    pub code: u32,
}
impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.vendor {
            Some(v) => write!(f, "{}-{}", v, self.code),
            None => write!(f, "{}", self.code),
        }
    }
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SizeFlag {
    Any,             // no size constraint (default)
    Exact(u32),      // size=16
    Range(u32, u32), // size=1-253
}

impl SizeFlag {
    pub fn is_constrained(&self) -> bool {
        !matches!(self, SizeFlag::Any)
    }
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DictionaryValue {
    pub attribute_name: String,
    pub name: String,
    pub value: u64,
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DictionaryVendor {
    pub name: String,
    pub code: u32,
    pub attributes: Vec<DictionaryAttribute>,
    pub values: Vec<DictionaryValue>,
}
