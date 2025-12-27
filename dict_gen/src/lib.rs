use dict_parser::dictionary::{AttributeType, Dictionary, DictionaryAttribute, DictionaryValue};
use heck::{ToPascalCase, ToShoutySnakeCase, ToSnakeCase};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use std::collections::{HashMap, HashSet};
pub mod rfc2865;

pub struct Generator {
    pub module_name: String,
    pub ignored_attributes: Vec<String>,
    /// Maps attribute names to the crate/module path for external definitions
    pub external_attributes: HashMap<String, String>,
}

impl Generator {
    pub fn new(module_name: &str) -> Self {
        Self {
            module_name: module_name.to_string(),
            ignored_attributes: Vec::new(),
            external_attributes: HashMap::new(),
        }
    }
    /// Strict validation based on RADIUS protocol and generator.go logic
    fn validate_attr(&self, attr: &DictionaryAttribute) -> Result<(), String> {
        // OID Check: Standard attributes must fit in 1 byte
        if attr.oid.vendor.is_none() && attr.oid.code > 255 {
            return Err(format!(
                "Standard attribute {} OID must be <= 255",
                attr.name
            ));
        }

        // Size Check: Only String/Octets support size constraints
        if attr.size.is_constrained()
            && !matches!(
                attr.attr_type,
                AttributeType::String | AttributeType::Octets
            )
        {
            return Err(format!(
                "Size constraint invalid for non-binary type in {}",
                attr.name
            ));
        }

        // Encryption: Only specific flags (User-Password/Tunnel) supported
        if let Some(enc) = attr.encrypt {
            if enc != 1 && enc != 2 {
                return Err(format!(
                    "Unsupported encryption type {} on {}",
                    enc, attr.name
                ));
            }
        }

        // Concat: Strict rules (no encryption/tag/size allowed with concat)
        if attr.concat.unwrap_or(false) {
            let is_binary = matches!(
                attr.attr_type,
                AttributeType::String | AttributeType::Octets
            );
            let flags_present =
                attr.encrypt.is_some() || attr.has_tag.is_some() || attr.size.is_constrained();
            if !is_binary || flags_present {
                return Err(format!("Invalid Concat configuration for {}", attr.name));
            }
        }

        Ok(())
    }

    pub fn generate(&self, dict: &Dictionary) -> Result<String, Box<dyn std::error::Error>> {
        let mut tokens = TokenStream::new();
        let mut trait_signatures = TokenStream::new();
        let mut trait_impl_bodies = TokenStream::new();

        let trait_ident = format_ident!("{}Ext", self.module_name.to_pascal_case());
        let ignored: HashSet<_> = self.ignored_attributes.iter().collect();

        // 1. Group Values by Attribute Name for easier lookup
        let mut value_map: HashMap<String, Vec<&DictionaryValue>> = HashMap::new();
        for val in &dict.values {
            value_map
                .entry(val.attribute_name.clone())
                .or_default()
                .push(val);
        }

        // 2. Base Imports
        tokens.extend(quote! {
            use std::net::{Ipv4Addr, Ipv6Addr};
            use radius_core::{Packet};
        });

        // 3. Process Standard Attributes
        for attr in &dict.attributes {
            self.process_attribute(
                attr,
                &ignored,
                &value_map,
                &mut tokens,
                &mut trait_signatures,
                &mut trait_impl_bodies,
            );
        }

        // 4. Process Vendors and their specific Attributes/Values
        for vendor in &dict.vendors {
            let vendor_id = vendor.code;
            let vendor_const = format_ident!("VENDOR_{}", vendor.name.to_shouty_snake_case());

            tokens.extend(quote! { pub const #vendor_const: u32 = #vendor_id; });

            // Create a specific value map for this vendor
            let mut vendor_val_map: HashMap<String, Vec<&DictionaryValue>> = HashMap::new();
            for val in &vendor.values {
                vendor_val_map
                    .entry(val.attribute_name.clone())
                    .or_default()
                    .push(val);
            }

            for attr in &vendor.attributes {
                self.process_attribute(
                    attr,
                    &ignored,
                    &vendor_val_map,
                    &mut tokens,
                    &mut trait_signatures,
                    &mut trait_impl_bodies,
                );
            }
        }

        // 5. Wrap in Trait
        tokens.extend(quote! {
            pub trait #trait_ident {
                #trait_signatures
            }
            impl #trait_ident for Packet {
                #trait_impl_bodies
            }
        });

        Ok(tokens.to_string())
    }

    fn process_attribute(
        &self,
        attr: &DictionaryAttribute,
        ignored: &HashSet<&String>,
        value_map: &HashMap<String, Vec<&DictionaryValue>>,
        tokens: &mut TokenStream,
        signatures: &mut TokenStream,
        bodies: &mut TokenStream,
    ) {
        if ignored.contains(&attr.name) {
            return;
        }
        if let Err(e) = self.validate_attr(attr) {
            eprintln!("Skipping {}: {}", attr.name, e);
            return;
        }

        let is_external = self.external_attributes.contains_key(&attr.name);
        let const_ident = format_ident!("{}_TYPE", attr.name.to_shouty_snake_case());

        // A. Generate constants for the Attribute Type
        if !is_external {
            let code = attr.oid.code as u8;
            tokens.extend(quote! { pub const #const_ident: u8 = #code; });
        }

        // B. Generate Value Constants (Enums)
        if let Some(values) = value_map.get(&attr.name) {
            for val in values {
                let val_ident = format_ident!(
                    "{}_{}",
                    attr.name.to_shouty_snake_case(),
                    val.name.to_shouty_snake_case()
                );
                let val_lit = val.value;
                tokens.extend(quote! { pub const #val_ident: u64 = #val_lit; });
            }
        }

        // C. Build Method Dispatch Logic
        let get_ident = format_ident!("get_{}", attr.name.to_snake_case());
        let set_ident = format_ident!("set_{}", attr.name.to_snake_case());

        let (call_get, call_set) = if let Some(vid) = attr.oid.vendor {
            let v_const = format_ident!("VENDOR_{}", vid); // Ideally look up vendor name
            (
                quote! { self.get_vsa_attribute(#v_const, #const_ident) },
                quote! { self.set_vsa_attribute(#v_const, #const_ident, value) },
            )
        } else {
            (
                quote! { self.get_attribute(#const_ident) },
                quote! { self.set_attribute(#const_ident, value.to_vec()) },
            )
        };

        // D. Generate Type-Specific Signatures and Implementations
        match attr.attr_type {
            AttributeType::String | AttributeType::Octets => {
                signatures.extend(quote! {
                    fn #get_ident(&self) -> Option<&[u8]>;
                    fn #set_ident(&mut self, value: &[u8]);
                });
                bodies.extend(quote! {
                    fn #get_ident(&self) -> Option<&[u8]> { #call_get.map(|v| v.as_slice()) }
                    fn #set_ident(&mut self, value: &[u8]) { #call_set; }
                });
            }
            AttributeType::Integer | AttributeType::Date => {
                signatures.extend(quote! {
                    fn #get_ident(&self) -> Option<u32>;
                    fn #set_ident(&mut self, value: u32);
                });
                bodies.extend(quote! {
                    fn #get_ident(&self) -> Option<u32> {
                        #call_get.and_then(|v| {
                            let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
                            Some(u32::from_be_bytes(bytes))
                        })
                    }
                    fn #set_ident(&mut self, value: u32) {
                        let value = value.to_be_bytes(); // Returns [u8; 4]
                        #call_set; // This will now work because call_set uses value.to_vec() or similar
                    }
                });
            }
            AttributeType::IpAddr => {
                signatures.extend(quote! {
                    fn #get_ident(&self) -> Option<Ipv4Addr>;
                    fn #set_ident(&mut self, value: Ipv4Addr);
                });
                bodies.extend(quote! {
                    fn #get_ident(&self) -> Option<Ipv4Addr> {
                        #call_get.and_then(|v| {
                            let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
                            Some(Ipv4Addr::from(bytes))
                        })
                    }
                    fn #set_ident(&mut self, value: Ipv4Addr) {
                        let value = value.octets(); // Returns [u8; 4]
                        #call_set;
                    }
                });
            }

            _ => {} // Implement Ipv6, etc., following the same pattern
        }
    }
}
