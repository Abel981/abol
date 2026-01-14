use std::fmt;
use thiserror::Error;

/// Represents a complete RADIUS dictionary containing standard attributes,
/// values for enumerated types, and vendor-specific definitions.
#[derive(Default, Clone, Debug)]
pub struct Dictionary {
    /// List of standard (non-vendor) RADIUS attributes.
    pub attributes: Vec<DictionaryAttribute>,
    /// Enumerated value mappings for attributes (e.g., Service-Type values).
    pub values: Vec<DictionaryValue>,
    /// Vendor definitions including their unique VSAs.
    pub vendors: Vec<DictionaryVendor>,
}
impl Dictionary {
    /// Merges two dictionaries into a single combined dictionary.
    ///
    /// This performs strict validation to ensure there are no collisions between
    /// attribute names, OIDs, or vendor definitions.
    ///
    /// # Errors
    /// Returns `DictionaryError::Conflict` if:
    /// * Standard attribute names or OIDs collide.
    /// * Vendor IDs or names are inconsistent between dictionaries.
    /// * Attributes within a specific vendor collide.
    pub fn merge(d1: &Dictionary, d2: &Dictionary) -> Result<Dictionary, DictionaryError> {
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
/// The Object Identifier (OID) for a RADIUS attribute, consisting of
/// an optional vendor ID and the attribute code.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Oid {
    /// The SMI Private Enterprise Number (PEN). None for standard attributes.
    pub vendor: Option<u32>,
    /// The attribute type code (0-255 for standard, vendor-specific for VSAs).
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
/// Flags representing size constraints on attribute values.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub enum SizeFlag {
    /// No constraint (default).
    #[default]
    Any,
    /// Value must be exactly N bytes.
    Exact(u32),
    /// Value must be between N and M bytes (inclusive).
    Range(u32, u32),
}

impl SizeFlag {
    pub fn is_constrained(&self) -> bool {
        !matches!(self, SizeFlag::Any)
    }
}
/// A mapping between a string name and a numeric value for an attribute.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DictionaryValue {
    /// The name of the attribute this value belongs to.
    pub attribute_name: String,
    /// The name of the specific value (e.g., "Access-Request").
    pub name: String,
    /// The numeric representation of the value.
    pub value: u64,
}
/// A RADIUS Vendor definition.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DictionaryVendor {
    /// The name of the vendor (e.g., "Cisco").
    pub name: String,
    /// The SMI Private Enterprise Number.
    pub code: u32,
    /// Attributes specific to this vendor.
    pub attributes: Vec<DictionaryAttribute>,
    /// Enumerated value mappings for this vendor's attributes.
    pub values: Vec<DictionaryValue>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_attr(name: &str, code: u32) -> DictionaryAttribute {
        DictionaryAttribute {
            name: name.to_string(),
            oid: Oid { vendor: None, code },
            attr_type: AttributeType::Integer,
            size: SizeFlag::Any,
            encrypt: None,
            has_tag: None,
            concat: None,
        }
    }

    #[test]
    fn test_merge_success() {
        let mut d1 = Dictionary::default();
        d1.attributes.push(mock_attr("User-Name", 1));

        let mut d2 = Dictionary::default();
        d2.attributes.push(mock_attr("Password", 2));

        let merged = Dictionary::merge(&d1, &d2).unwrap();
        assert_eq!(merged.attributes.len(), 2);
    }

    #[test]
    fn test_merge_conflict_name() {
        let mut d1 = Dictionary::default();
        d1.attributes.push(mock_attr("User-Name", 1));

        let mut d2 = Dictionary::default();
        d2.attributes.push(mock_attr("User-Name", 2)); // Conflict on name

        let result = Dictionary::merge(&d1, &d2);
        assert!(matches!(result, Err(DictionaryError::Conflict(m)) if m.contains("name")));
    }

    #[test]
    fn test_merge_conflict_oid() {
        let mut d1 = Dictionary::default();
        d1.attributes.push(mock_attr("User-Name", 1));

        let mut d2 = Dictionary::default();
        d2.attributes.push(mock_attr("Login-Name", 1)); // Conflict on OID

        let result = Dictionary::merge(&d1, &d2);
        assert!(matches!(result, Err(DictionaryError::Conflict(m)) if m.contains("OID")));
    }

    #[test]
    fn test_vendor_merge_and_conflict() {
        let v1 = DictionaryVendor {
            name: "Cisco".to_string(),
            code: 9,
            attributes: vec![mock_attr("Cisco-AVPair", 1)],
            values: vec![],
        };

        let mut d1 = Dictionary::default();
        d1.vendors.push(v1);

        // Case 1: Merge different attributes into same vendor
        let v2 = DictionaryVendor {
            name: "Cisco".to_string(),
            code: 9,
            attributes: vec![mock_attr("Cisco-Other", 2)],
            values: vec![],
        };
        let mut d2 = Dictionary::default();
        d2.vendors.push(v2);

        let merged = Dictionary::merge(&d1, &d2).expect("Should merge vendor attributes");
        assert_eq!(merged.vendors[0].attributes.len(), 2);

        // Case 2: Conflict on vendor attribute OID
        let v3 = DictionaryVendor {
            name: "Cisco".to_string(),
            code: 9,
            attributes: vec![mock_attr("Cisco-Duplicate", 1)], // OID 1 already exists in d1's Cisco vendor
            values: vec![],
        };
        let mut d3 = Dictionary::default();
        d3.vendors.push(v3);

        let result = Dictionary::merge(&d1, &d3);
        assert!(result.is_err());
    }

    #[test]
    fn test_vendor_mismatch_definition() {
        let mut d1 = Dictionary::default();
        d1.vendors.push(DictionaryVendor {
            name: "Cisco".to_string(),
            code: 9,
            attributes: vec![],
            values: vec![],
        });

        let mut d2 = Dictionary::default();
        d2.vendors.push(DictionaryVendor {
            name: "Cisco".to_string(),
            code: 10, // Same name, different code
            attributes: vec![],
            values: vec![],
        });

        let result = Dictionary::merge(&d1, &d2);
        assert!(matches!(result, Err(DictionaryError::Conflict(_))));
    }
}
