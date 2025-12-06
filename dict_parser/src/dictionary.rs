pub struct Dictionary {
    pub attributes: Vec<DictionaryAttribute>,
    pub values: Vec<DictionaryValue>,
    pub vendors: Vec<DictionaryVendor>,
}
#[derive(Clone)]
pub enum AttributeType {
    String,
    Integer,
    IpAddr,
    Octets,
    Date,
    Vsa,
    Ifid,
    Ipv6Addr,
    Ipv6Prefix,
    InterfaceId,
    //todo check unknown type and add all attributes
    Unknown(String),
}
#[derive(Clone)]
pub struct DictionaryAttribute {
    pub name: String,
    pub oid: Oid,
    pub attr_type: AttributeType,
    pub size: SizeFlag,
    pub encrypt: Option<u8>,
    pub has_tag: Option<bool>,
    pub concat: Option<bool>,
}
#[derive(Clone)]
pub struct Oid {
    pub vendor: Option<u32>,
    pub code: u32,
}
#[derive(Clone)]
pub enum SizeFlag {
    Any,             // no size constraint (default)
    Exact(u32),      // size=16
    Range(u32, u32), // size=1-253
}
#[derive(Clone)]
pub struct DictionaryValue {
    pub attribute_name: String,
    pub name: String,
    pub value: u64,
}
#[derive(Clone)]
pub struct DictionaryVendor {
    pub name: String,
    pub code: u32,
    pub attributes: Vec<DictionaryAttribute>,
    pub values: Vec<DictionaryValue>,
}
