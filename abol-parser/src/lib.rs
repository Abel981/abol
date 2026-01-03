pub mod dictionary;

use std::{
    collections::HashSet,
    fmt::format,
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};

use crate::dictionary::{
    AttributeType, DictionaryAttribute, DictionaryValue, DictionaryVendor, Oid, SizeFlag,
};

pub struct AttributeFlags {
    pub encrypt: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct FileOpener {
    root: PathBuf,
}

impl FileOpener {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root_path = root.into();
        // Canonicalize the root immediately to turn relative paths (like ../)
        // into absolute system paths for reliable security checks.
        let canonical_root = root_path.canonicalize().unwrap_or(root_path);
        Self {
            root: canonical_root,
        }
    }

    pub fn get_root(&self) -> &Path {
        &self.root
    }

    pub fn open_file(&self, relative_path: impl AsRef<Path>) -> Result<File> {
        let relative_path = relative_path.as_ref();
        let full_path = if relative_path.is_absolute() {
            relative_path.to_path_buf()
        } else {
            self.root.join(relative_path)
        };
        let abs_path = full_path
            .canonicalize()
            .with_context(|| format!("failed to resolve absolute path for {:?}", full_path))?;
        ensure!(
            abs_path.starts_with(&self.root),
            "attempted to open file {:?} outside of root {:?}",
            abs_path,
            self.root
        );
        let file =
            File::open(&abs_path).with_context(|| format!("failed to open file {:?}", abs_path))?;
        println!("Opened file {:?}", abs_path);
        Ok(file)
    }
}

pub struct Parser {
    pub file_opener: FileOpener,
    pub ignore_identical_attributes: bool,
}

impl Parser {
    pub fn new(file_opener: FileOpener, ignore_identical_attributes: bool) -> Self {
        Self {
            file_opener,
            ignore_identical_attributes,
        }
    }

    pub fn parse_dictionary(&self, file_path: impl AsRef<Path>) -> Result<dictionary::Dictionary> {
        // initialize empty dictionary
        let mut dict = dictionary::Dictionary {
            attributes: Vec::new(),
            values: Vec::new(),
            vendors: Vec::new(),
        };

        let file = self.file_opener.open_file(&file_path)?;
        let mut parsed = HashSet::new();
        let p = file_path.as_ref();
        let full_path = if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.file_opener.get_root().join(p) // Access the absolute root from FileOpener
        };
        // let canonical = Self::canonical_path(&file_path)?;
        parsed.insert(full_path);
        self.parse(&mut dict, &mut parsed, file)?;
        Ok(dict)
    }

    fn parse(
        &self,
        dict: &mut dictionary::Dictionary,
        parsed_files: &mut HashSet<PathBuf>,
        file: File,
    ) -> Result<()> {
        let reader = BufReader::new(file);
        // vendor_block holds a temporary mutable vendor while inside BEGIN-VENDOR..END-VENDOR
        let mut vendor_block: Option<DictionaryVendor> = None;

        for (idx, raw_line) in reader.lines().enumerate() {
            let line_no = idx + 1;
            let mut line = raw_line.with_context(|| format!("reading line {}", line_no))?;
            if let Some(comment_start) = line.find('#') {
                line.truncate(comment_start);
            }
            if line.trim().is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();

            match () {
                // ATTRIBUTE lines: "ATTRIBUTE <name> <type> <oid> [encrypt]"
                _ if (fields.len() == 4 || fields.len() == 5) && fields[0] == "ATTRIBUTE" => {
                    let attr = self
                        .parse_attribute(&fields)
                        .map_err(|e| anyhow::anyhow!("line {}: {}", line_no, e))?;

                    let existing = if vendor_block.is_none() {
                        attribute_by_name(&dict.attributes, &attr.name)
                    } else {
                        vendor_block
                            .as_ref()
                            .and_then(|v| attribute_by_name(&v.attributes, &attr.name))
                    };

                    if let Some(existing_attr) = existing {
                        if self.ignore_identical_attributes && attr == *existing_attr {
                            // skip if identical and ignoring identical
                            continue;
                        }
                        bail!("line {}: duplicate attribute '{}'", line_no, attr.name);
                    }

                    if let Some(vb) = vendor_block.as_mut() {
                        vb.attributes.push(attr);
                    } else {
                        dict.attributes.push(attr);
                    }
                }

                // VALUE lines: "VALUE <attribute_name> <name> <value>"
                _ if fields.len() == 4 && fields[0] == "VALUE" => {
                    let value = self
                        .parse_value(&fields)
                        .map_err(|e| anyhow::anyhow!("line {}: {}", line_no, e))?;
                    if let Some(vb) = vendor_block.as_mut() {
                        vb.values.push(value);
                    } else {
                        dict.values.push(value);
                    }
                }

                // VENDOR lines: "VENDOR <name> <code>"
                _ if (fields.len() == 3 || fields.len() == 4) && fields[0] == "VENDOR" => {
                    let vendor = self
                        .parse_vendor(&fields)
                        .map_err(|e| anyhow::anyhow!("line {}: {}", line_no, e))?;
                    if vendor_by_name_or_number(&dict.vendors, &vendor.name, vendor.code).is_some()
                    {
                        bail!("line {}: duplicate vendor '{}'", line_no, vendor.name);
                    }
                    dict.vendors.push(vendor);
                }

                // BEGIN-VENDOR <name>
                _ if fields.len() == 2 && fields[0] == "BEGIN-VENDOR" => {
                    if vendor_block.is_some() {
                        bail!("line {}: nested vendor block not allowed", line_no);
                    }
                    let vendor = vendor_by_name(&dict.vendors, fields[1])
                        .ok_or_else(|| {
                            anyhow::anyhow!("line {}: unknown vendor '{}'", line_no, fields[1])
                        })?
                        .clone();
                    vendor_block = Some(vendor);
                }

                // END-VENDOR <name>
                _ if fields.len() == 2 && fields[0] == "END-VENDOR" => {
                    if vendor_block.is_none() {
                        bail!("line {}: unmatched END-VENDOR", line_no);
                    }
                    if vendor_block.as_ref().unwrap().name != fields[1] {
                        bail!(
                            "line {}: invalid END-VENDOR '{}', expected '{}'",
                            line_no,
                            fields[1],
                            vendor_block.as_ref().unwrap().name
                        );
                    }
                    // commit vendor_block back into dict (replace existing vendor entry)
                    let vb = vendor_block.take().unwrap();
                    if let Some(pos) = dict.vendors.iter().position(|v| v.name == vb.name) {
                        dict.vendors[pos] = vb;
                    } else {
                        dict.vendors.push(vb);
                    }
                }

                // $INCLUDE <path>
                _ if fields.len() == 2 && fields[0] == "$INCLUDE" => {
                    if vendor_block.is_some() {
                        bail!("line {}: $INCLUDE not allowed inside vendor block", line_no);
                    }
                    let include_path = fields[1];
                    let include_path = PathBuf::from(include_path);
                    let inc_file =
                        self.file_opener.open_file(&include_path).with_context(|| {
                            format!(
                                "line {}: failed to open include {}",
                                line_no,
                                include_path.display()
                            )
                        })?;
                    let inc_canonical = Self::canonical_path(&include_path)?;
                    if parsed_files.contains(&inc_canonical) {
                        bail!(
                            "line {}: recursive include {}",
                            line_no,
                            include_path.display()
                        );
                    }
                    parsed_files.insert(inc_canonical.clone());
                    self.parse(dict, parsed_files, inc_file)?;
                }

                _ => {
                    bail!("line {}: unknown line: {}", line_no, line);
                }
            }
        }

        if vendor_block.is_some() {
            bail!("unclosed vendor block at EOF");
        }

        Ok(())
    }

    // fields: &[&str] expected from split_whitespace
    fn parse_attribute(&self, fields: &[&str]) -> std::result::Result<DictionaryAttribute, String> {
        // Expected: ATTRIBUTE <name> <type> <oid> [encrypt]
        if fields.len() < 4 {
            return Err("ATTRIBUTE line too short".into());
        }
        let name = fields[1].to_string();
        let attr_type = Self::parse_attribute_type(fields[3])?;
        let oid = parse_oid(fields[2])?;
        let size = SizeFlag::Any; // TODO: parse explicit size if present in extended dialect
        let encrypt = if fields.len() == 5 {
            let encrypt_val = fields[4];
            let Some((_, value)) = encrypt_val.split_once('=') else {
                return Err("invalid encrypt format".into());
            };
            Some(
                value
                    .parse::<u8>()
                    .map_err(|e| format!("invalid encrypt: {}", e))?,
            )
        } else {
            None
        };

        Ok(DictionaryAttribute {
            name,
            oid,
            attr_type,
            size,
            encrypt,
            has_tag: None,
            concat: None,
        })
    }

    fn parse_value(&self, fields: &[&str]) -> std::result::Result<DictionaryValue, String> {
        // Expected: VALUE <attribute_name> <name> <value>
        if fields.len() != 4 {
            return Err("VALUE line must have 4 fields".into());
        }
        let attribute_name = fields[1].to_string();
        let name = fields[2].to_string();
        let value = fields[3]
            .parse::<u64>()
            .map_err(|e| format!("invalid value: {}", e))?;
        Ok(DictionaryValue {
            attribute_name,
            name,
            value,
        })
    }

    fn parse_vendor(&self, fields: &[&str]) -> std::result::Result<DictionaryVendor, String> {
        // Expected: VENDOR <name> <code>
        if fields.len() < 3 {
            return Err("VENDOR line too short".into());
        }
        let name = fields[1].to_string();
        let code = fields[2]
            .parse::<u32>()
            .map_err(|e| format!("invalid vendor code: {}", e))?;
        Ok(DictionaryVendor {
            name,
            code,
            // NOTE: we assume DictionaryVendor has attributes & values vectors
            attributes: Vec::new(),
            values: Vec::new(),
        })
    }

    fn canonical_path(p: &impl AsRef<Path>) -> Result<PathBuf> {
        let path = p.as_ref();

        let abs_path = path
            .canonicalize()
            .with_context(|| format!("failed to resolve absolute path for {:?}", path))?;

        Ok(abs_path)
    }

    fn parse_attribute_type(s: &str) -> std::result::Result<AttributeType, String> {
        Ok(match s.to_lowercase().as_str() {
            "string" => AttributeType::String,
            "integer" => AttributeType::Integer,
            "ipaddr" => AttributeType::IpAddr,
            "octets" => AttributeType::Octets,
            "date" => AttributeType::Date,
            "tlv" => AttributeType::Tlv,
            "byte" => AttributeType::Byte,
            "short" => AttributeType::Short,
            "signed" => AttributeType::Signed,
            "ipv4prefix" => AttributeType::Ipv4Prefix,
            "vsa" => AttributeType::Vsa,
            "ifid" => AttributeType::Ifid,
            "ipv6addr" => AttributeType::Ipv6Addr,
            "ipv6prefix" => AttributeType::Ipv6Prefix,
            "interface-id" => AttributeType::InterfaceId,
            other => AttributeType::Unknown(other.to_string()),
        })
    }
}

// Helper functions (module-level)

fn parse_oid(s: &str) -> std::result::Result<Oid, String> {
    // Support formats: "<code>" or "<vendor>:<code>"
    if let Some(idx) = s.find(':') {
        let vendor = s[..idx]
            .parse::<u32>()
            .map_err(|e| format!("invalid vendor id: {}", e))?;
        let code = s[idx + 1..]
            .parse::<u32>()
            .map_err(|e| format!("invalid code: {}", e))?;
        Ok(Oid {
            vendor: Some(vendor),
            code,
        })
    } else {
        let code = s
            .parse::<u32>()
            .map_err(|e| format!("invalid code: {}", e))?;
        Ok(Oid { vendor: None, code })
    }
}

fn attribute_by_name<'a>(
    attrs: &'a [DictionaryAttribute],
    name: &str,
) -> Option<&'a DictionaryAttribute> {
    attrs.iter().find(|a| a.name == name)
}

fn vendor_by_name<'a>(vendors: &'a [DictionaryVendor], name: &str) -> Option<&'a DictionaryVendor> {
    vendors.iter().find(|v| v.name == name)
}

fn vendor_by_name_or_number<'a>(
    vendors: &'a [DictionaryVendor],
    name: &str,
    code: u32,
) -> Option<&'a DictionaryVendor> {
    vendors.iter().find(|v| v.name == name || v.code == code)
}
