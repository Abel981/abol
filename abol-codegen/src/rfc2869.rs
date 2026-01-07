use abol_core::{attribute::FromRadiusAttribute, attribute::ToRadiusAttribute, packet::Packet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;
pub const ACCT_INPUT_GIGAWORDS_TYPE: u8 = 52u8;
pub const ACCT_OUTPUT_GIGAWORDS_TYPE: u8 = 53u8;
pub const EVENT_TIMESTAMP_TYPE: u8 = 55u8;
pub const ARAP_PASSWORD_TYPE: u8 = 70u8;
pub const ARAP_FEATURES_TYPE: u8 = 71u8;
pub const ARAP_ZONE_ACCESS_TYPE: u8 = 72u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ArapZoneAccess {
    DefaultZone,
    ZoneFilterInclusive,
    ZoneFilterExclusive,
    Unknown(u32),
}
impl From<u32> for ArapZoneAccess {
    fn from(v: u32) -> Self {
        match v {
            1u32 => Self::DefaultZone,
            2u32 => Self::ZoneFilterInclusive,
            4u32 => Self::ZoneFilterExclusive,
            other => Self::Unknown(other),
        }
    }
}
impl From<ArapZoneAccess> for u32 {
    fn from(e: ArapZoneAccess) -> Self {
        match e {
            ArapZoneAccess::DefaultZone => 1u32,
            ArapZoneAccess::ZoneFilterInclusive => 2u32,
            ArapZoneAccess::ZoneFilterExclusive => 4u32,
            ArapZoneAccess::Unknown(v) => v,
        }
    }
}
pub const ARAP_SECURITY_TYPE: u8 = 73u8;
pub const ARAP_SECURITY_DATA_TYPE: u8 = 74u8;
pub const PASSWORD_RETRY_TYPE: u8 = 75u8;
pub const PROMPT_TYPE: u8 = 76u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Prompt {
    NoEcho,
    Echo,
    Unknown(u32),
}
impl From<u32> for Prompt {
    fn from(v: u32) -> Self {
        match v {
            0u32 => Self::NoEcho,
            1u32 => Self::Echo,
            other => Self::Unknown(other),
        }
    }
}
impl From<Prompt> for u32 {
    fn from(e: Prompt) -> Self {
        match e {
            Prompt::NoEcho => 0u32,
            Prompt::Echo => 1u32,
            Prompt::Unknown(v) => v,
        }
    }
}
pub const CONNECT_INFO_TYPE: u8 = 77u8;
pub const CONFIGURATION_TOKEN_TYPE: u8 = 78u8;
pub const EAP_MESSAGE_TYPE: u8 = 79u8;
pub const MESSAGE_AUTHENTICATOR_TYPE: u8 = 80u8;
pub const ARAP_CHALLENGE_RESPONSE_TYPE: u8 = 84u8;
pub const ACCT_INTERIM_INTERVAL_TYPE: u8 = 85u8;
pub const NAS_PORT_ID_TYPE: u8 = 87u8;
pub const FRAMED_POOL_TYPE: u8 = 88u8;
pub trait Rfc2869Ext {
    fn get_acct_input_gigawords(&self) -> Option<u32>;
    fn set_acct_input_gigawords(&mut self, value: u32);
    fn get_acct_output_gigawords(&self) -> Option<u32>;
    fn set_acct_output_gigawords(&mut self, value: u32);
    fn get_event_timestamp(&self) -> Option<SystemTime>;
    fn set_event_timestamp(&mut self, value: SystemTime);
    fn get_arap_password(&self) -> Option<Vec<u8>>;
    fn set_arap_password(&mut self, value: impl Into<Vec<u8>>);
    fn get_arap_features(&self) -> Option<Vec<u8>>;
    fn set_arap_features(&mut self, value: impl Into<Vec<u8>>);
    fn get_arap_zone_access(&self) -> Option<ArapZoneAccess>;
    fn set_arap_zone_access(&mut self, value: ArapZoneAccess);
    fn get_arap_security(&self) -> Option<u32>;
    fn set_arap_security(&mut self, value: u32);
    fn get_arap_security_data(&self) -> Option<String>;
    fn set_arap_security_data(&mut self, value: impl Into<String>);
    fn get_password_retry(&self) -> Option<u32>;
    fn set_password_retry(&mut self, value: u32);
    fn get_prompt(&self) -> Option<Prompt>;
    fn set_prompt(&mut self, value: Prompt);
    fn get_connect_info(&self) -> Option<String>;
    fn set_connect_info(&mut self, value: impl Into<String>);
    fn get_configuration_token(&self) -> Option<String>;
    fn set_configuration_token(&mut self, value: impl Into<String>);
    fn get_eap_message(&self) -> Option<Vec<u8>>;
    fn set_eap_message(&mut self, value: impl Into<Vec<u8>>);
    fn get_message_authenticator(&self) -> Option<Vec<u8>>;
    fn set_message_authenticator(&mut self, value: impl Into<Vec<u8>>);
    fn get_arap_challenge_response(&self) -> Option<Vec<u8>>;
    fn set_arap_challenge_response(&mut self, value: impl Into<Vec<u8>>);
    fn get_acct_interim_interval(&self) -> Option<u32>;
    fn set_acct_interim_interval(&mut self, value: u32);
    fn get_nas_port_id(&self) -> Option<String>;
    fn set_nas_port_id(&mut self, value: impl Into<String>);
    fn get_framed_pool(&self) -> Option<String>;
    fn set_framed_pool(&mut self, value: impl Into<String>);
}
impl Rfc2869Ext for Packet {
    fn get_acct_input_gigawords(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(ACCT_INPUT_GIGAWORDS_TYPE)
    }
    fn set_acct_input_gigawords(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ACCT_INPUT_GIGAWORDS_TYPE, wire_val);
    }
    fn get_acct_output_gigawords(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(ACCT_OUTPUT_GIGAWORDS_TYPE)
    }
    fn set_acct_output_gigawords(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ACCT_OUTPUT_GIGAWORDS_TYPE, wire_val);
    }
    fn get_event_timestamp(&self) -> Option<SystemTime> {
        self.get_attribute_as::<SystemTime>(EVENT_TIMESTAMP_TYPE)
    }
    fn set_event_timestamp(&mut self, value: SystemTime) {
        let wire_val: SystemTime = value.into();
        self.set_attribute_as::<SystemTime>(EVENT_TIMESTAMP_TYPE, wire_val);
    }
    fn get_arap_password(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(ARAP_PASSWORD_TYPE)
    }
    fn set_arap_password(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        if ToRadiusAttribute::to_bytes(&wire_val).len() != 16u32 as usize {
            return;
        }
        self.set_attribute_as::<Vec<u8>>(ARAP_PASSWORD_TYPE, wire_val);
    }
    fn get_arap_features(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(ARAP_FEATURES_TYPE)
    }
    fn set_arap_features(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        if ToRadiusAttribute::to_bytes(&wire_val).len() != 14u32 as usize {
            return;
        }
        self.set_attribute_as::<Vec<u8>>(ARAP_FEATURES_TYPE, wire_val);
    }
    fn get_arap_zone_access(&self) -> Option<ArapZoneAccess> {
        self.get_attribute_as::<u32>(ARAP_ZONE_ACCESS_TYPE)
            .map(ArapZoneAccess::from)
    }
    fn set_arap_zone_access(&mut self, value: ArapZoneAccess) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ARAP_ZONE_ACCESS_TYPE, wire_val);
    }
    fn get_arap_security(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(ARAP_SECURITY_TYPE)
    }
    fn set_arap_security(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ARAP_SECURITY_TYPE, wire_val);
    }
    fn get_arap_security_data(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARAP_SECURITY_DATA_TYPE)
    }
    fn set_arap_security_data(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARAP_SECURITY_DATA_TYPE, wire_val);
    }
    fn get_password_retry(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(PASSWORD_RETRY_TYPE)
    }
    fn set_password_retry(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(PASSWORD_RETRY_TYPE, wire_val);
    }
    fn get_prompt(&self) -> Option<Prompt> {
        self.get_attribute_as::<u32>(PROMPT_TYPE).map(Prompt::from)
    }
    fn set_prompt(&mut self, value: Prompt) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(PROMPT_TYPE, wire_val);
    }
    fn get_connect_info(&self) -> Option<String> {
        self.get_attribute_as::<String>(CONNECT_INFO_TYPE)
    }
    fn set_connect_info(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(CONNECT_INFO_TYPE, wire_val);
    }
    fn get_configuration_token(&self) -> Option<String> {
        self.get_attribute_as::<String>(CONFIGURATION_TOKEN_TYPE)
    }
    fn set_configuration_token(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(CONFIGURATION_TOKEN_TYPE, wire_val);
    }
    fn get_eap_message(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(EAP_MESSAGE_TYPE)
    }
    fn set_eap_message(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(EAP_MESSAGE_TYPE, wire_val);
    }
    fn get_message_authenticator(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MESSAGE_AUTHENTICATOR_TYPE)
    }
    fn set_message_authenticator(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(MESSAGE_AUTHENTICATOR_TYPE, wire_val);
    }
    fn get_arap_challenge_response(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(ARAP_CHALLENGE_RESPONSE_TYPE)
    }
    fn set_arap_challenge_response(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        if ToRadiusAttribute::to_bytes(&wire_val).len() != 8u32 as usize {
            return;
        }
        self.set_attribute_as::<Vec<u8>>(ARAP_CHALLENGE_RESPONSE_TYPE, wire_val);
    }
    fn get_acct_interim_interval(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(ACCT_INTERIM_INTERVAL_TYPE)
    }
    fn set_acct_interim_interval(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ACCT_INTERIM_INTERVAL_TYPE, wire_val);
    }
    fn get_nas_port_id(&self) -> Option<String> {
        self.get_attribute_as::<String>(NAS_PORT_ID_TYPE)
    }
    fn set_nas_port_id(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(NAS_PORT_ID_TYPE, wire_val);
    }
    fn get_framed_pool(&self) -> Option<String> {
        self.get_attribute_as::<String>(FRAMED_POOL_TYPE)
    }
    fn set_framed_pool(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(FRAMED_POOL_TYPE, wire_val);
    }
}
