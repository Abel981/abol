use abol_core::{attribute::FromRadiusAttribute, attribute::ToRadiusAttribute, packet::Packet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;
pub const ACCT_STATUS_TYPE_TYPE: u8 = 40u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AcctStatusType {
    Start,
    Stop,
    Alive,
    InterimUpdate,
    AccountingOn,
    AccountingOff,
    Failed,
    Unknown(u32),
}
impl From<u32> for AcctStatusType {
    fn from(v: u32) -> Self {
        match v {
            1u32 => Self::Start,
            2u32 => Self::Stop,
            3u32 => Self::Alive,
            7u32 => Self::AccountingOn,
            8u32 => Self::AccountingOff,
            15u32 => Self::Failed,
            other => Self::Unknown(other),
        }
    }
}
impl From<AcctStatusType> for u32 {
    fn from(e: AcctStatusType) -> Self {
        match e {
            AcctStatusType::Start => 1u32,
            AcctStatusType::Stop => 2u32,
            AcctStatusType::Alive => 3u32,
            AcctStatusType::InterimUpdate => 3u32,
            AcctStatusType::AccountingOn => 7u32,
            AcctStatusType::AccountingOff => 8u32,
            AcctStatusType::Failed => 15u32,
            AcctStatusType::Unknown(v) => v,
        }
    }
}
pub const ACCT_DELAY_TIME_TYPE: u8 = 41u8;
pub const ACCT_INPUT_OCTETS_TYPE: u8 = 42u8;
pub const ACCT_OUTPUT_OCTETS_TYPE: u8 = 43u8;
pub const ACCT_SESSION_ID_TYPE: u8 = 44u8;
pub const ACCT_AUTHENTIC_TYPE: u8 = 45u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AcctAuthentic {
    Radius,
    Local,
    Remote,
    Diameter,
    Unknown(u32),
}
impl From<u32> for AcctAuthentic {
    fn from(v: u32) -> Self {
        match v {
            1u32 => Self::Radius,
            2u32 => Self::Local,
            3u32 => Self::Remote,
            4u32 => Self::Diameter,
            other => Self::Unknown(other),
        }
    }
}
impl From<AcctAuthentic> for u32 {
    fn from(e: AcctAuthentic) -> Self {
        match e {
            AcctAuthentic::Radius => 1u32,
            AcctAuthentic::Local => 2u32,
            AcctAuthentic::Remote => 3u32,
            AcctAuthentic::Diameter => 4u32,
            AcctAuthentic::Unknown(v) => v,
        }
    }
}
pub const ACCT_SESSION_TIME_TYPE: u8 = 46u8;
pub const ACCT_INPUT_PACKETS_TYPE: u8 = 47u8;
pub const ACCT_OUTPUT_PACKETS_TYPE: u8 = 48u8;
pub const ACCT_TERMINATE_CAUSE_TYPE: u8 = 49u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AcctTerminateCause {
    UserRequest,
    LostCarrier,
    LostService,
    IdleTimeout,
    SessionTimeout,
    AdminReset,
    AdminReboot,
    PortError,
    NasError,
    NasRequest,
    NasReboot,
    PortUnneeded,
    PortPreempted,
    PortSuspended,
    ServiceUnavailable,
    Callback,
    UserError,
    HostRequest,
    Unknown(u32),
}
impl From<u32> for AcctTerminateCause {
    fn from(v: u32) -> Self {
        match v {
            1u32 => Self::UserRequest,
            2u32 => Self::LostCarrier,
            3u32 => Self::LostService,
            4u32 => Self::IdleTimeout,
            5u32 => Self::SessionTimeout,
            6u32 => Self::AdminReset,
            7u32 => Self::AdminReboot,
            8u32 => Self::PortError,
            9u32 => Self::NasError,
            10u32 => Self::NasRequest,
            11u32 => Self::NasReboot,
            12u32 => Self::PortUnneeded,
            13u32 => Self::PortPreempted,
            14u32 => Self::PortSuspended,
            15u32 => Self::ServiceUnavailable,
            16u32 => Self::Callback,
            17u32 => Self::UserError,
            18u32 => Self::HostRequest,
            other => Self::Unknown(other),
        }
    }
}
impl From<AcctTerminateCause> for u32 {
    fn from(e: AcctTerminateCause) -> Self {
        match e {
            AcctTerminateCause::UserRequest => 1u32,
            AcctTerminateCause::LostCarrier => 2u32,
            AcctTerminateCause::LostService => 3u32,
            AcctTerminateCause::IdleTimeout => 4u32,
            AcctTerminateCause::SessionTimeout => 5u32,
            AcctTerminateCause::AdminReset => 6u32,
            AcctTerminateCause::AdminReboot => 7u32,
            AcctTerminateCause::PortError => 8u32,
            AcctTerminateCause::NasError => 9u32,
            AcctTerminateCause::NasRequest => 10u32,
            AcctTerminateCause::NasReboot => 11u32,
            AcctTerminateCause::PortUnneeded => 12u32,
            AcctTerminateCause::PortPreempted => 13u32,
            AcctTerminateCause::PortSuspended => 14u32,
            AcctTerminateCause::ServiceUnavailable => 15u32,
            AcctTerminateCause::Callback => 16u32,
            AcctTerminateCause::UserError => 17u32,
            AcctTerminateCause::HostRequest => 18u32,
            AcctTerminateCause::Unknown(v) => v,
        }
    }
}
pub const ACCT_MULTI_SESSION_ID_TYPE: u8 = 50u8;
pub const ACCT_LINK_COUNT_TYPE: u8 = 51u8;
pub trait Rfc2866Ext {
    fn get_acct_status_type(&self) -> Option<AcctStatusType>;
    fn set_acct_status_type(&mut self, value: AcctStatusType);
    fn get_acct_delay_time(&self) -> Option<u32>;
    fn set_acct_delay_time(&mut self, value: u32);
    fn get_acct_input_octets(&self) -> Option<u32>;
    fn set_acct_input_octets(&mut self, value: u32);
    fn get_acct_output_octets(&self) -> Option<u32>;
    fn set_acct_output_octets(&mut self, value: u32);
    fn get_acct_session_id(&self) -> Option<String>;
    fn set_acct_session_id(&mut self, value: impl Into<String>);
    fn get_acct_authentic(&self) -> Option<AcctAuthentic>;
    fn set_acct_authentic(&mut self, value: AcctAuthentic);
    fn get_acct_session_time(&self) -> Option<u32>;
    fn set_acct_session_time(&mut self, value: u32);
    fn get_acct_input_packets(&self) -> Option<u32>;
    fn set_acct_input_packets(&mut self, value: u32);
    fn get_acct_output_packets(&self) -> Option<u32>;
    fn set_acct_output_packets(&mut self, value: u32);
    fn get_acct_terminate_cause(&self) -> Option<AcctTerminateCause>;
    fn set_acct_terminate_cause(&mut self, value: AcctTerminateCause);
    fn get_acct_multi_session_id(&self) -> Option<String>;
    fn set_acct_multi_session_id(&mut self, value: impl Into<String>);
    fn get_acct_link_count(&self) -> Option<u32>;
    fn set_acct_link_count(&mut self, value: u32);
}
impl Rfc2866Ext for Packet {
    fn get_acct_status_type(&self) -> Option<AcctStatusType> {
        self.get_attribute_as::<u32>(ACCT_STATUS_TYPE_TYPE)
            .map(AcctStatusType::from)
    }
    fn set_acct_status_type(&mut self, value: AcctStatusType) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ACCT_STATUS_TYPE_TYPE, wire_val);
    }
    fn get_acct_delay_time(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(ACCT_DELAY_TIME_TYPE)
    }
    fn set_acct_delay_time(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ACCT_DELAY_TIME_TYPE, wire_val);
    }
    fn get_acct_input_octets(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(ACCT_INPUT_OCTETS_TYPE)
    }
    fn set_acct_input_octets(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ACCT_INPUT_OCTETS_TYPE, wire_val);
    }
    fn get_acct_output_octets(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(ACCT_OUTPUT_OCTETS_TYPE)
    }
    fn set_acct_output_octets(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ACCT_OUTPUT_OCTETS_TYPE, wire_val);
    }
    fn get_acct_session_id(&self) -> Option<String> {
        self.get_attribute_as::<String>(ACCT_SESSION_ID_TYPE)
    }
    fn set_acct_session_id(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ACCT_SESSION_ID_TYPE, wire_val);
    }
    fn get_acct_authentic(&self) -> Option<AcctAuthentic> {
        self.get_attribute_as::<u32>(ACCT_AUTHENTIC_TYPE)
            .map(AcctAuthentic::from)
    }
    fn set_acct_authentic(&mut self, value: AcctAuthentic) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ACCT_AUTHENTIC_TYPE, wire_val);
    }
    fn get_acct_session_time(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(ACCT_SESSION_TIME_TYPE)
    }
    fn set_acct_session_time(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ACCT_SESSION_TIME_TYPE, wire_val);
    }
    fn get_acct_input_packets(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(ACCT_INPUT_PACKETS_TYPE)
    }
    fn set_acct_input_packets(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ACCT_INPUT_PACKETS_TYPE, wire_val);
    }
    fn get_acct_output_packets(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(ACCT_OUTPUT_PACKETS_TYPE)
    }
    fn set_acct_output_packets(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ACCT_OUTPUT_PACKETS_TYPE, wire_val);
    }
    fn get_acct_terminate_cause(&self) -> Option<AcctTerminateCause> {
        self.get_attribute_as::<u32>(ACCT_TERMINATE_CAUSE_TYPE)
            .map(AcctTerminateCause::from)
    }
    fn set_acct_terminate_cause(&mut self, value: AcctTerminateCause) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ACCT_TERMINATE_CAUSE_TYPE, wire_val);
    }
    fn get_acct_multi_session_id(&self) -> Option<String> {
        self.get_attribute_as::<String>(ACCT_MULTI_SESSION_ID_TYPE)
    }
    fn set_acct_multi_session_id(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ACCT_MULTI_SESSION_ID_TYPE, wire_val);
    }
    fn get_acct_link_count(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(ACCT_LINK_COUNT_TYPE)
    }
    fn set_acct_link_count(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ACCT_LINK_COUNT_TYPE, wire_val);
    }
}
