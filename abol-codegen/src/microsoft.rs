use abol_core::{attribute::FromRadiusAttribute, attribute::ToRadiusAttribute, packet::Packet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;
pub const VENDOR_MICROSOFT: u32 = 311u32;
pub const MS_CHAP_RESPONSE_TYPE: u8 = 1u8;
pub const MS_CHAP_ERROR_TYPE: u8 = 2u8;
pub const MS_CHAP_CPW_1_TYPE: u8 = 3u8;
pub const MS_CHAP_CPW_2_TYPE: u8 = 4u8;
pub const MS_CHAP_LM_ENC_PW_TYPE: u8 = 5u8;
pub const MS_CHAP_NT_ENC_PW_TYPE: u8 = 6u8;
pub const MS_MPPE_ENCRYPTION_POLICY_TYPE: u8 = 7u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MsMppeEncryptionPolicy {
    EncryptionAllowed,
    EncryptionRequired,
    Unknown(u32),
}
impl From<u32> for MsMppeEncryptionPolicy {
    fn from(v: u32) -> Self {
        match v {
            1u32 => Self::EncryptionAllowed,
            2u32 => Self::EncryptionRequired,
            other => Self::Unknown(other),
        }
    }
}
impl From<MsMppeEncryptionPolicy> for u32 {
    fn from(e: MsMppeEncryptionPolicy) -> Self {
        match e {
            MsMppeEncryptionPolicy::EncryptionAllowed => 1u32,
            MsMppeEncryptionPolicy::EncryptionRequired => 2u32,
            MsMppeEncryptionPolicy::Unknown(v) => v,
        }
    }
}
pub const MS_MPPE_ENCRYPTION_TYPE_TYPE: u8 = 8u8;
pub const MS_MPPE_ENCRYPTION_TYPES_TYPE: u8 = 8u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MsMppeEncryptionTypes {
    Rc440bitAllowed,
    Rc4128bitAllowed,
    Rc440or128BitAllowed,
    Unknown(u32),
}
impl From<u32> for MsMppeEncryptionTypes {
    fn from(v: u32) -> Self {
        match v {
            1u32 => Self::Rc440bitAllowed,
            2u32 => Self::Rc4128bitAllowed,
            6u32 => Self::Rc440or128BitAllowed,
            other => Self::Unknown(other),
        }
    }
}
impl From<MsMppeEncryptionTypes> for u32 {
    fn from(e: MsMppeEncryptionTypes) -> Self {
        match e {
            MsMppeEncryptionTypes::Rc440bitAllowed => 1u32,
            MsMppeEncryptionTypes::Rc4128bitAllowed => 2u32,
            MsMppeEncryptionTypes::Rc440or128BitAllowed => 6u32,
            MsMppeEncryptionTypes::Unknown(v) => v,
        }
    }
}
pub const MS_RAS_VENDOR_TYPE: u8 = 9u8;
pub const MS_CHAP_DOMAIN_TYPE: u8 = 10u8;
pub const MS_CHAP_CHALLENGE_TYPE: u8 = 11u8;
pub const MS_CHAP_MPPE_KEYS_TYPE: u8 = 12u8;
pub const MS_BAP_USAGE_TYPE: u8 = 13u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MsBapUsage {
    NotAllowed,
    Allowed,
    Required,
    Unknown(u32),
}
impl From<u32> for MsBapUsage {
    fn from(v: u32) -> Self {
        match v {
            0u32 => Self::NotAllowed,
            1u32 => Self::Allowed,
            2u32 => Self::Required,
            other => Self::Unknown(other),
        }
    }
}
impl From<MsBapUsage> for u32 {
    fn from(e: MsBapUsage) -> Self {
        match e {
            MsBapUsage::NotAllowed => 0u32,
            MsBapUsage::Allowed => 1u32,
            MsBapUsage::Required => 2u32,
            MsBapUsage::Unknown(v) => v,
        }
    }
}
pub const MS_LINK_UTILIZATION_THRESHOLD_TYPE: u8 = 14u8;
pub const MS_LINK_DROP_TIME_LIMIT_TYPE: u8 = 15u8;
pub const MS_MPPE_SEND_KEY_TYPE: u8 = 16u8;
pub const MS_MPPE_RECV_KEY_TYPE: u8 = 17u8;
pub const MS_RAS_VERSION_TYPE: u8 = 18u8;
pub const MS_OLD_ARAP_PASSWORD_TYPE: u8 = 19u8;
pub const MS_NEW_ARAP_PASSWORD_TYPE: u8 = 20u8;
pub const MS_ARAP_PW_CHANGE_REASON_TYPE: u8 = 21u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MsArapPwChangeReason {
    JustChangePassword,
    ExpiredPassword,
    AdminRequiresPasswordChange,
    PasswordTooShort,
    Unknown(u32),
}
impl From<u32> for MsArapPwChangeReason {
    fn from(v: u32) -> Self {
        match v {
            1u32 => Self::JustChangePassword,
            2u32 => Self::ExpiredPassword,
            3u32 => Self::AdminRequiresPasswordChange,
            4u32 => Self::PasswordTooShort,
            other => Self::Unknown(other),
        }
    }
}
impl From<MsArapPwChangeReason> for u32 {
    fn from(e: MsArapPwChangeReason) -> Self {
        match e {
            MsArapPwChangeReason::JustChangePassword => 1u32,
            MsArapPwChangeReason::ExpiredPassword => 2u32,
            MsArapPwChangeReason::AdminRequiresPasswordChange => 3u32,
            MsArapPwChangeReason::PasswordTooShort => 4u32,
            MsArapPwChangeReason::Unknown(v) => v,
        }
    }
}
pub const MS_FILTER_TYPE: u8 = 22u8;
pub const MS_ACCT_AUTH_TYPE_TYPE: u8 = 23u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MsAcctAuthType {
    Pap,
    Chap,
    MsChap1,
    MsChap2,
    Eap,
    Unknown(u32),
}
impl From<u32> for MsAcctAuthType {
    fn from(v: u32) -> Self {
        match v {
            1u32 => Self::Pap,
            2u32 => Self::Chap,
            3u32 => Self::MsChap1,
            4u32 => Self::MsChap2,
            5u32 => Self::Eap,
            other => Self::Unknown(other),
        }
    }
}
impl From<MsAcctAuthType> for u32 {
    fn from(e: MsAcctAuthType) -> Self {
        match e {
            MsAcctAuthType::Pap => 1u32,
            MsAcctAuthType::Chap => 2u32,
            MsAcctAuthType::MsChap1 => 3u32,
            MsAcctAuthType::MsChap2 => 4u32,
            MsAcctAuthType::Eap => 5u32,
            MsAcctAuthType::Unknown(v) => v,
        }
    }
}
pub const MS_ACCT_EAP_TYPE_TYPE: u8 = 24u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MsAcctEapType {
    Md5,
    Otp,
    GenericTokenCard,
    Tls,
    Unknown(u32),
}
impl From<u32> for MsAcctEapType {
    fn from(v: u32) -> Self {
        match v {
            4u32 => Self::Md5,
            5u32 => Self::Otp,
            6u32 => Self::GenericTokenCard,
            13u32 => Self::Tls,
            other => Self::Unknown(other),
        }
    }
}
impl From<MsAcctEapType> for u32 {
    fn from(e: MsAcctEapType) -> Self {
        match e {
            MsAcctEapType::Md5 => 4u32,
            MsAcctEapType::Otp => 5u32,
            MsAcctEapType::GenericTokenCard => 6u32,
            MsAcctEapType::Tls => 13u32,
            MsAcctEapType::Unknown(v) => v,
        }
    }
}
pub const MS_CHAP2_RESPONSE_TYPE: u8 = 25u8;
pub const MS_CHAP2_SUCCESS_TYPE: u8 = 26u8;
pub const MS_CHAP2_CPW_TYPE: u8 = 27u8;
pub const MS_PRIMARY_DNS_SERVER_TYPE: u8 = 28u8;
pub const MS_SECONDARY_DNS_SERVER_TYPE: u8 = 29u8;
pub const MS_PRIMARY_NBNS_SERVER_TYPE: u8 = 30u8;
pub const MS_SECONDARY_NBNS_SERVER_TYPE: u8 = 31u8;
pub const MS_RAS_CLIENT_NAME_TYPE: u8 = 34u8;
pub const MS_RAS_CLIENT_VERSION_TYPE: u8 = 35u8;
pub const MS_QUARANTINE_IPFILTER_TYPE: u8 = 36u8;
pub const MS_QUARANTINE_SESSION_TIMEOUT_TYPE: u8 = 37u8;
pub const MS_USER_SECURITY_IDENTITY_TYPE: u8 = 40u8;
pub const MS_IDENTITY_TYPE_TYPE: u8 = 41u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MsIdentityType {
    MachineHealthCheck,
    IgnoreUserLookupFailure,
    Unknown(u32),
}
impl From<u32> for MsIdentityType {
    fn from(v: u32) -> Self {
        match v {
            1u32 => Self::MachineHealthCheck,
            2u32 => Self::IgnoreUserLookupFailure,
            other => Self::Unknown(other),
        }
    }
}
impl From<MsIdentityType> for u32 {
    fn from(e: MsIdentityType) -> Self {
        match e {
            MsIdentityType::MachineHealthCheck => 1u32,
            MsIdentityType::IgnoreUserLookupFailure => 2u32,
            MsIdentityType::Unknown(v) => v,
        }
    }
}
pub const MS_SERVICE_CLASS_TYPE: u8 = 42u8;
pub const MS_QUARANTINE_USER_CLASS_TYPE: u8 = 44u8;
pub const MS_QUARANTINE_STATE_TYPE: u8 = 45u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MsQuarantineState {
    FullAccess,
    Quarantine,
    Probation,
    Unknown(u32),
}
impl From<u32> for MsQuarantineState {
    fn from(v: u32) -> Self {
        match v {
            0u32 => Self::FullAccess,
            1u32 => Self::Quarantine,
            2u32 => Self::Probation,
            other => Self::Unknown(other),
        }
    }
}
impl From<MsQuarantineState> for u32 {
    fn from(e: MsQuarantineState) -> Self {
        match e {
            MsQuarantineState::FullAccess => 0u32,
            MsQuarantineState::Quarantine => 1u32,
            MsQuarantineState::Probation => 2u32,
            MsQuarantineState::Unknown(v) => v,
        }
    }
}
pub const MS_QUARANTINE_GRACE_TIME_TYPE: u8 = 46u8;
pub const MS_NETWORK_ACCESS_SERVER_TYPE_TYPE: u8 = 47u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MsNetworkAccessServerType {
    Unspecified,
    TerminalServerGateway,
    RemoteAccessServer,
    DhcpServer,
    WirelessAccessPoint,
    Hra,
    HcapServer,
    Unknown(u32),
}
impl From<u32> for MsNetworkAccessServerType {
    fn from(v: u32) -> Self {
        match v {
            0u32 => Self::Unspecified,
            1u32 => Self::TerminalServerGateway,
            2u32 => Self::RemoteAccessServer,
            3u32 => Self::DhcpServer,
            4u32 => Self::WirelessAccessPoint,
            5u32 => Self::Hra,
            6u32 => Self::HcapServer,
            other => Self::Unknown(other),
        }
    }
}
impl From<MsNetworkAccessServerType> for u32 {
    fn from(e: MsNetworkAccessServerType) -> Self {
        match e {
            MsNetworkAccessServerType::Unspecified => 0u32,
            MsNetworkAccessServerType::TerminalServerGateway => 1u32,
            MsNetworkAccessServerType::RemoteAccessServer => 2u32,
            MsNetworkAccessServerType::DhcpServer => 3u32,
            MsNetworkAccessServerType::WirelessAccessPoint => 4u32,
            MsNetworkAccessServerType::Hra => 5u32,
            MsNetworkAccessServerType::HcapServer => 6u32,
            MsNetworkAccessServerType::Unknown(v) => v,
        }
    }
}
pub const MS_AFW_ZONE_TYPE: u8 = 48u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MsAfwZone {
    MsAfwZoneBoundaryPolicy,
    MsAfwZoneUnprotectedPolicy,
    MsAfwZoneProtectedPolicy,
    Unknown(u32),
}
impl From<u32> for MsAfwZone {
    fn from(v: u32) -> Self {
        match v {
            1u32 => Self::MsAfwZoneBoundaryPolicy,
            2u32 => Self::MsAfwZoneUnprotectedPolicy,
            3u32 => Self::MsAfwZoneProtectedPolicy,
            other => Self::Unknown(other),
        }
    }
}
impl From<MsAfwZone> for u32 {
    fn from(e: MsAfwZone) -> Self {
        match e {
            MsAfwZone::MsAfwZoneBoundaryPolicy => 1u32,
            MsAfwZone::MsAfwZoneUnprotectedPolicy => 2u32,
            MsAfwZone::MsAfwZoneProtectedPolicy => 3u32,
            MsAfwZone::Unknown(v) => v,
        }
    }
}
pub const MS_AFW_PROTECTION_LEVEL_TYPE: u8 = 49u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MsAfwProtectionLevel {
    HecpResponseSignOnly,
    HecpResponseSignAndEncrypt,
    Unknown(u32),
}
impl From<u32> for MsAfwProtectionLevel {
    fn from(v: u32) -> Self {
        match v {
            1u32 => Self::HecpResponseSignOnly,
            2u32 => Self::HecpResponseSignAndEncrypt,
            other => Self::Unknown(other),
        }
    }
}
impl From<MsAfwProtectionLevel> for u32 {
    fn from(e: MsAfwProtectionLevel) -> Self {
        match e {
            MsAfwProtectionLevel::HecpResponseSignOnly => 1u32,
            MsAfwProtectionLevel::HecpResponseSignAndEncrypt => 2u32,
            MsAfwProtectionLevel::Unknown(v) => v,
        }
    }
}
pub const MS_MACHINE_NAME_TYPE: u8 = 50u8;
pub const MS_IPV6_FILTER_TYPE: u8 = 51u8;
pub const MS_IPV4_REMEDIATION_SERVERS_TYPE: u8 = 52u8;
pub const MS_IPV6_REMEDIATION_SERVERS_TYPE: u8 = 53u8;
pub const MS_RNAP_NOT_QUARANTINE_CAPABLE_TYPE: u8 = 54u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MsRnapNotQuarantineCapable {
    SoHSent,
    SoHNotSent,
    Unknown(u32),
}
impl From<u32> for MsRnapNotQuarantineCapable {
    fn from(v: u32) -> Self {
        match v {
            0u32 => Self::SoHSent,
            1u32 => Self::SoHNotSent,
            other => Self::Unknown(other),
        }
    }
}
impl From<MsRnapNotQuarantineCapable> for u32 {
    fn from(e: MsRnapNotQuarantineCapable) -> Self {
        match e {
            MsRnapNotQuarantineCapable::SoHSent => 0u32,
            MsRnapNotQuarantineCapable::SoHNotSent => 1u32,
            MsRnapNotQuarantineCapable::Unknown(v) => v,
        }
    }
}
pub const MS_QUARANTINE_SOH_TYPE: u8 = 55u8;
pub const MS_RAS_CORRELATION_TYPE: u8 = 56u8;
pub const MS_EXTENDED_QUARANTINE_STATE_TYPE: u8 = 57u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MsExtendedQuarantineState {
    Transition,
    Infected,
    Unknown,
    NoData,
    Other(u32),
}
impl From<u32> for MsExtendedQuarantineState {
    fn from(v: u32) -> Self {
        match v {
            1u32 => Self::Transition,
            2u32 => Self::Infected,
            3u32 => Self::Unknown,
            4u32 => Self::NoData,
            other => Self::Other(other),
        }
    }
}
impl From<MsExtendedQuarantineState> for u32 {
    fn from(e: MsExtendedQuarantineState) -> Self {
        match e {
            MsExtendedQuarantineState::Transition => 1u32,
            MsExtendedQuarantineState::Infected => 2u32,
            MsExtendedQuarantineState::Unknown => 3u32,
            MsExtendedQuarantineState::NoData => 4u32,
            MsExtendedQuarantineState::Other(v) => v,
        }
    }
}
pub const MS_HCAP_USER_GROUPS_TYPE: u8 = 58u8;
pub const MS_HCAP_LOCATION_GROUP_NAME_TYPE: u8 = 59u8;
pub const MS_HCAP_USER_NAME_TYPE: u8 = 60u8;
pub const MS_USER_IPV4_ADDRESS_TYPE: u8 = 61u8;
pub const MS_USER_IPV6_ADDRESS_TYPE: u8 = 62u8;
pub const MS_TSG_DEVICE_REDIRECTION_TYPE: u8 = 63u8;
pub trait MicrosoftExt {
    fn get_ms_chap_response(&self) -> Option<Vec<u8>>;
    fn set_ms_chap_response(&mut self, value: impl Into<Vec<u8>>);
    fn get_ms_chap_error(&self) -> Option<String>;
    fn set_ms_chap_error(&mut self, value: impl Into<String>);
    fn get_ms_chap_cpw_1(&self) -> Option<Vec<u8>>;
    fn set_ms_chap_cpw_1(&mut self, value: impl Into<Vec<u8>>);
    fn get_ms_chap_cpw_2(&self) -> Option<Vec<u8>>;
    fn set_ms_chap_cpw_2(&mut self, value: impl Into<Vec<u8>>);
    fn get_ms_chap_lm_enc_pw(&self) -> Option<Vec<u8>>;
    fn set_ms_chap_lm_enc_pw(&mut self, value: impl Into<Vec<u8>>);
    fn get_ms_chap_nt_enc_pw(&self) -> Option<Vec<u8>>;
    fn set_ms_chap_nt_enc_pw(&mut self, value: impl Into<Vec<u8>>);
    fn get_ms_mppe_encryption_policy(&self) -> Option<MsMppeEncryptionPolicy>;
    fn set_ms_mppe_encryption_policy(&mut self, value: MsMppeEncryptionPolicy);
    fn get_ms_mppe_encryption_type(&self) -> Option<u32>;
    fn set_ms_mppe_encryption_type(&mut self, value: u32);
    fn get_ms_mppe_encryption_types(&self) -> Option<MsMppeEncryptionTypes>;
    fn set_ms_mppe_encryption_types(&mut self, value: MsMppeEncryptionTypes);
    fn get_ms_ras_vendor(&self) -> Option<u32>;
    fn set_ms_ras_vendor(&mut self, value: u32);
    fn get_ms_chap_domain(&self) -> Option<String>;
    fn set_ms_chap_domain(&mut self, value: impl Into<String>);
    fn get_ms_chap_challenge(&self) -> Option<Vec<u8>>;
    fn set_ms_chap_challenge(&mut self, value: impl Into<Vec<u8>>);
    fn get_ms_chap_mppe_keys(&self) -> Option<Vec<u8>>;
    fn set_ms_chap_mppe_keys(&mut self, value: impl Into<Vec<u8>>);
    fn get_ms_bap_usage(&self) -> Option<MsBapUsage>;
    fn set_ms_bap_usage(&mut self, value: MsBapUsage);
    fn get_ms_link_utilization_threshold(&self) -> Option<u32>;
    fn set_ms_link_utilization_threshold(&mut self, value: u32);
    fn get_ms_link_drop_time_limit(&self) -> Option<u32>;
    fn set_ms_link_drop_time_limit(&mut self, value: u32);
    fn get_ms_mppe_send_key(&self) -> Option<Vec<u8>>;
    fn set_ms_mppe_send_key(&mut self, value: impl Into<Vec<u8>>);
    fn get_ms_mppe_recv_key(&self) -> Option<Vec<u8>>;
    fn set_ms_mppe_recv_key(&mut self, value: impl Into<Vec<u8>>);
    fn get_ms_ras_version(&self) -> Option<String>;
    fn set_ms_ras_version(&mut self, value: impl Into<String>);
    fn get_ms_old_arap_password(&self) -> Option<Vec<u8>>;
    fn set_ms_old_arap_password(&mut self, value: impl Into<Vec<u8>>);
    fn get_ms_new_arap_password(&self) -> Option<Vec<u8>>;
    fn set_ms_new_arap_password(&mut self, value: impl Into<Vec<u8>>);
    fn get_ms_arap_pw_change_reason(&self) -> Option<MsArapPwChangeReason>;
    fn set_ms_arap_pw_change_reason(&mut self, value: MsArapPwChangeReason);
    fn get_ms_filter(&self) -> Option<Vec<u8>>;
    fn set_ms_filter(&mut self, value: impl Into<Vec<u8>>);
    fn get_ms_acct_auth_type(&self) -> Option<MsAcctAuthType>;
    fn set_ms_acct_auth_type(&mut self, value: MsAcctAuthType);
    fn get_ms_acct_eap_type(&self) -> Option<MsAcctEapType>;
    fn set_ms_acct_eap_type(&mut self, value: MsAcctEapType);
    fn get_ms_chap2_response(&self) -> Option<Vec<u8>>;
    fn set_ms_chap2_response(&mut self, value: impl Into<Vec<u8>>);
    fn get_ms_chap2_success(&self) -> Option<Vec<u8>>;
    fn set_ms_chap2_success(&mut self, value: impl Into<Vec<u8>>);
    fn get_ms_chap2_cpw(&self) -> Option<Vec<u8>>;
    fn set_ms_chap2_cpw(&mut self, value: impl Into<Vec<u8>>);
    fn get_ms_primary_dns_server(&self) -> Option<Ipv4Addr>;
    fn set_ms_primary_dns_server(&mut self, value: Ipv4Addr);
    fn get_ms_secondary_dns_server(&self) -> Option<Ipv4Addr>;
    fn set_ms_secondary_dns_server(&mut self, value: Ipv4Addr);
    fn get_ms_primary_nbns_server(&self) -> Option<Ipv4Addr>;
    fn set_ms_primary_nbns_server(&mut self, value: Ipv4Addr);
    fn get_ms_secondary_nbns_server(&self) -> Option<Ipv4Addr>;
    fn set_ms_secondary_nbns_server(&mut self, value: Ipv4Addr);
    fn get_ms_ras_client_name(&self) -> Option<String>;
    fn set_ms_ras_client_name(&mut self, value: impl Into<String>);
    fn get_ms_ras_client_version(&self) -> Option<String>;
    fn set_ms_ras_client_version(&mut self, value: impl Into<String>);
    fn get_ms_quarantine_ipfilter(&self) -> Option<Vec<u8>>;
    fn set_ms_quarantine_ipfilter(&mut self, value: impl Into<Vec<u8>>);
    fn get_ms_quarantine_session_timeout(&self) -> Option<u32>;
    fn set_ms_quarantine_session_timeout(&mut self, value: u32);
    fn get_ms_user_security_identity(&self) -> Option<String>;
    fn set_ms_user_security_identity(&mut self, value: impl Into<String>);
    fn get_ms_identity_type(&self) -> Option<MsIdentityType>;
    fn set_ms_identity_type(&mut self, value: MsIdentityType);
    fn get_ms_service_class(&self) -> Option<String>;
    fn set_ms_service_class(&mut self, value: impl Into<String>);
    fn get_ms_quarantine_user_class(&self) -> Option<String>;
    fn set_ms_quarantine_user_class(&mut self, value: impl Into<String>);
    fn get_ms_quarantine_state(&self) -> Option<MsQuarantineState>;
    fn set_ms_quarantine_state(&mut self, value: MsQuarantineState);
    fn get_ms_quarantine_grace_time(&self) -> Option<u32>;
    fn set_ms_quarantine_grace_time(&mut self, value: u32);
    fn get_ms_network_access_server_type(&self) -> Option<MsNetworkAccessServerType>;
    fn set_ms_network_access_server_type(&mut self, value: MsNetworkAccessServerType);
    fn get_ms_afw_zone(&self) -> Option<MsAfwZone>;
    fn set_ms_afw_zone(&mut self, value: MsAfwZone);
    fn get_ms_afw_protection_level(&self) -> Option<MsAfwProtectionLevel>;
    fn set_ms_afw_protection_level(&mut self, value: MsAfwProtectionLevel);
    fn get_ms_machine_name(&self) -> Option<String>;
    fn set_ms_machine_name(&mut self, value: impl Into<String>);
    fn get_ms_ipv6_filter(&self) -> Option<Vec<u8>>;
    fn set_ms_ipv6_filter(&mut self, value: impl Into<Vec<u8>>);
    fn get_ms_ipv4_remediation_servers(&self) -> Option<Vec<u8>>;
    fn set_ms_ipv4_remediation_servers(&mut self, value: impl Into<Vec<u8>>);
    fn get_ms_ipv6_remediation_servers(&self) -> Option<Vec<u8>>;
    fn set_ms_ipv6_remediation_servers(&mut self, value: impl Into<Vec<u8>>);
    fn get_ms_rnap_not_quarantine_capable(&self) -> Option<MsRnapNotQuarantineCapable>;
    fn set_ms_rnap_not_quarantine_capable(&mut self, value: MsRnapNotQuarantineCapable);
    fn get_ms_quarantine_soh(&self) -> Option<Vec<u8>>;
    fn set_ms_quarantine_soh(&mut self, value: impl Into<Vec<u8>>);
    fn get_ms_ras_correlation(&self) -> Option<Vec<u8>>;
    fn set_ms_ras_correlation(&mut self, value: impl Into<Vec<u8>>);
    fn get_ms_extended_quarantine_state(&self) -> Option<MsExtendedQuarantineState>;
    fn set_ms_extended_quarantine_state(&mut self, value: MsExtendedQuarantineState);
    fn get_ms_hcap_user_groups(&self) -> Option<String>;
    fn set_ms_hcap_user_groups(&mut self, value: impl Into<String>);
    fn get_ms_hcap_location_group_name(&self) -> Option<String>;
    fn set_ms_hcap_location_group_name(&mut self, value: impl Into<String>);
    fn get_ms_hcap_user_name(&self) -> Option<String>;
    fn set_ms_hcap_user_name(&mut self, value: impl Into<String>);
    fn get_ms_user_ipv4_address(&self) -> Option<Ipv4Addr>;
    fn set_ms_user_ipv4_address(&mut self, value: Ipv4Addr);
    fn get_ms_user_ipv6_address(&self) -> Option<Ipv6Addr>;
    fn set_ms_user_ipv6_address(&mut self, value: Ipv6Addr);
    fn get_ms_tsg_device_redirection(&self) -> Option<u32>;
    fn set_ms_tsg_device_redirection(&mut self, value: u32);
}
impl MicrosoftExt for Packet {
    fn get_ms_chap_response(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MS_CHAP_RESPONSE_TYPE)
    }
    fn set_ms_chap_response(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        if ToRadiusAttribute::to_bytes(&wire_val).len() != 50u32 as usize {
            return;
        }
        self.set_attribute_as::<Vec<u8>>(MS_CHAP_RESPONSE_TYPE, wire_val);
    }
    fn get_ms_chap_error(&self) -> Option<String> {
        self.get_attribute_as::<String>(MS_CHAP_ERROR_TYPE)
    }
    fn set_ms_chap_error(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(MS_CHAP_ERROR_TYPE, wire_val);
    }
    fn get_ms_chap_cpw_1(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MS_CHAP_CPW_1_TYPE)
    }
    fn set_ms_chap_cpw_1(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        if ToRadiusAttribute::to_bytes(&wire_val).len() != 70u32 as usize {
            return;
        }
        self.set_attribute_as::<Vec<u8>>(MS_CHAP_CPW_1_TYPE, wire_val);
    }
    fn get_ms_chap_cpw_2(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MS_CHAP_CPW_2_TYPE)
    }
    fn set_ms_chap_cpw_2(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        if ToRadiusAttribute::to_bytes(&wire_val).len() != 84u32 as usize {
            return;
        }
        self.set_attribute_as::<Vec<u8>>(MS_CHAP_CPW_2_TYPE, wire_val);
    }
    fn get_ms_chap_lm_enc_pw(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MS_CHAP_LM_ENC_PW_TYPE)
    }
    fn set_ms_chap_lm_enc_pw(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(MS_CHAP_LM_ENC_PW_TYPE, wire_val);
    }
    fn get_ms_chap_nt_enc_pw(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MS_CHAP_NT_ENC_PW_TYPE)
    }
    fn set_ms_chap_nt_enc_pw(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(MS_CHAP_NT_ENC_PW_TYPE, wire_val);
    }
    fn get_ms_mppe_encryption_policy(&self) -> Option<MsMppeEncryptionPolicy> {
        self.get_attribute_as::<u32>(MS_MPPE_ENCRYPTION_POLICY_TYPE)
            .map(MsMppeEncryptionPolicy::from)
    }
    fn set_ms_mppe_encryption_policy(&mut self, value: MsMppeEncryptionPolicy) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(MS_MPPE_ENCRYPTION_POLICY_TYPE, wire_val);
    }
    fn get_ms_mppe_encryption_type(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(MS_MPPE_ENCRYPTION_TYPE_TYPE)
    }
    fn set_ms_mppe_encryption_type(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(MS_MPPE_ENCRYPTION_TYPE_TYPE, wire_val);
    }
    fn get_ms_mppe_encryption_types(&self) -> Option<MsMppeEncryptionTypes> {
        self.get_attribute_as::<u32>(MS_MPPE_ENCRYPTION_TYPES_TYPE)
            .map(MsMppeEncryptionTypes::from)
    }
    fn set_ms_mppe_encryption_types(&mut self, value: MsMppeEncryptionTypes) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(MS_MPPE_ENCRYPTION_TYPES_TYPE, wire_val);
    }
    fn get_ms_ras_vendor(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(MS_RAS_VENDOR_TYPE)
    }
    fn set_ms_ras_vendor(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(MS_RAS_VENDOR_TYPE, wire_val);
    }
    fn get_ms_chap_domain(&self) -> Option<String> {
        self.get_attribute_as::<String>(MS_CHAP_DOMAIN_TYPE)
    }
    fn set_ms_chap_domain(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(MS_CHAP_DOMAIN_TYPE, wire_val);
    }
    fn get_ms_chap_challenge(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MS_CHAP_CHALLENGE_TYPE)
    }
    fn set_ms_chap_challenge(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(MS_CHAP_CHALLENGE_TYPE, wire_val);
    }
    fn get_ms_chap_mppe_keys(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MS_CHAP_MPPE_KEYS_TYPE)
    }
    fn set_ms_chap_mppe_keys(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        if ToRadiusAttribute::to_bytes(&wire_val).len() != 24u32 as usize {
            return;
        }
        self.set_attribute_as::<Vec<u8>>(MS_CHAP_MPPE_KEYS_TYPE, wire_val);
    }
    fn get_ms_bap_usage(&self) -> Option<MsBapUsage> {
        self.get_attribute_as::<u32>(MS_BAP_USAGE_TYPE)
            .map(MsBapUsage::from)
    }
    fn set_ms_bap_usage(&mut self, value: MsBapUsage) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(MS_BAP_USAGE_TYPE, wire_val);
    }
    fn get_ms_link_utilization_threshold(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(MS_LINK_UTILIZATION_THRESHOLD_TYPE)
    }
    fn set_ms_link_utilization_threshold(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(MS_LINK_UTILIZATION_THRESHOLD_TYPE, wire_val);
    }
    fn get_ms_link_drop_time_limit(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(MS_LINK_DROP_TIME_LIMIT_TYPE)
    }
    fn set_ms_link_drop_time_limit(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(MS_LINK_DROP_TIME_LIMIT_TYPE, wire_val);
    }
    fn get_ms_mppe_send_key(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MS_MPPE_SEND_KEY_TYPE)
    }
    fn set_ms_mppe_send_key(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(MS_MPPE_SEND_KEY_TYPE, wire_val);
    }
    fn get_ms_mppe_recv_key(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MS_MPPE_RECV_KEY_TYPE)
    }
    fn set_ms_mppe_recv_key(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(MS_MPPE_RECV_KEY_TYPE, wire_val);
    }
    fn get_ms_ras_version(&self) -> Option<String> {
        self.get_attribute_as::<String>(MS_RAS_VERSION_TYPE)
    }
    fn set_ms_ras_version(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(MS_RAS_VERSION_TYPE, wire_val);
    }
    fn get_ms_old_arap_password(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MS_OLD_ARAP_PASSWORD_TYPE)
    }
    fn set_ms_old_arap_password(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(MS_OLD_ARAP_PASSWORD_TYPE, wire_val);
    }
    fn get_ms_new_arap_password(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MS_NEW_ARAP_PASSWORD_TYPE)
    }
    fn set_ms_new_arap_password(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(MS_NEW_ARAP_PASSWORD_TYPE, wire_val);
    }
    fn get_ms_arap_pw_change_reason(&self) -> Option<MsArapPwChangeReason> {
        self.get_attribute_as::<u32>(MS_ARAP_PW_CHANGE_REASON_TYPE)
            .map(MsArapPwChangeReason::from)
    }
    fn set_ms_arap_pw_change_reason(&mut self, value: MsArapPwChangeReason) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(MS_ARAP_PW_CHANGE_REASON_TYPE, wire_val);
    }
    fn get_ms_filter(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MS_FILTER_TYPE)
    }
    fn set_ms_filter(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(MS_FILTER_TYPE, wire_val);
    }
    fn get_ms_acct_auth_type(&self) -> Option<MsAcctAuthType> {
        self.get_attribute_as::<u32>(MS_ACCT_AUTH_TYPE_TYPE)
            .map(MsAcctAuthType::from)
    }
    fn set_ms_acct_auth_type(&mut self, value: MsAcctAuthType) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(MS_ACCT_AUTH_TYPE_TYPE, wire_val);
    }
    fn get_ms_acct_eap_type(&self) -> Option<MsAcctEapType> {
        self.get_attribute_as::<u32>(MS_ACCT_EAP_TYPE_TYPE)
            .map(MsAcctEapType::from)
    }
    fn set_ms_acct_eap_type(&mut self, value: MsAcctEapType) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(MS_ACCT_EAP_TYPE_TYPE, wire_val);
    }
    fn get_ms_chap2_response(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MS_CHAP2_RESPONSE_TYPE)
    }
    fn set_ms_chap2_response(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        if ToRadiusAttribute::to_bytes(&wire_val).len() != 50u32 as usize {
            return;
        }
        self.set_attribute_as::<Vec<u8>>(MS_CHAP2_RESPONSE_TYPE, wire_val);
    }
    fn get_ms_chap2_success(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MS_CHAP2_SUCCESS_TYPE)
    }
    fn set_ms_chap2_success(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(MS_CHAP2_SUCCESS_TYPE, wire_val);
    }
    fn get_ms_chap2_cpw(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MS_CHAP2_CPW_TYPE)
    }
    fn set_ms_chap2_cpw(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        if ToRadiusAttribute::to_bytes(&wire_val).len() != 68u32 as usize {
            return;
        }
        self.set_attribute_as::<Vec<u8>>(MS_CHAP2_CPW_TYPE, wire_val);
    }
    fn get_ms_primary_dns_server(&self) -> Option<Ipv4Addr> {
        self.get_attribute_as::<Ipv4Addr>(MS_PRIMARY_DNS_SERVER_TYPE)
    }
    fn set_ms_primary_dns_server(&mut self, value: Ipv4Addr) {
        let wire_val: Ipv4Addr = value.into();
        self.set_attribute_as::<Ipv4Addr>(MS_PRIMARY_DNS_SERVER_TYPE, wire_val);
    }
    fn get_ms_secondary_dns_server(&self) -> Option<Ipv4Addr> {
        self.get_attribute_as::<Ipv4Addr>(MS_SECONDARY_DNS_SERVER_TYPE)
    }
    fn set_ms_secondary_dns_server(&mut self, value: Ipv4Addr) {
        let wire_val: Ipv4Addr = value.into();
        self.set_attribute_as::<Ipv4Addr>(MS_SECONDARY_DNS_SERVER_TYPE, wire_val);
    }
    fn get_ms_primary_nbns_server(&self) -> Option<Ipv4Addr> {
        self.get_attribute_as::<Ipv4Addr>(MS_PRIMARY_NBNS_SERVER_TYPE)
    }
    fn set_ms_primary_nbns_server(&mut self, value: Ipv4Addr) {
        let wire_val: Ipv4Addr = value.into();
        self.set_attribute_as::<Ipv4Addr>(MS_PRIMARY_NBNS_SERVER_TYPE, wire_val);
    }
    fn get_ms_secondary_nbns_server(&self) -> Option<Ipv4Addr> {
        self.get_attribute_as::<Ipv4Addr>(MS_SECONDARY_NBNS_SERVER_TYPE)
    }
    fn set_ms_secondary_nbns_server(&mut self, value: Ipv4Addr) {
        let wire_val: Ipv4Addr = value.into();
        self.set_attribute_as::<Ipv4Addr>(MS_SECONDARY_NBNS_SERVER_TYPE, wire_val);
    }
    fn get_ms_ras_client_name(&self) -> Option<String> {
        self.get_attribute_as::<String>(MS_RAS_CLIENT_NAME_TYPE)
    }
    fn set_ms_ras_client_name(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(MS_RAS_CLIENT_NAME_TYPE, wire_val);
    }
    fn get_ms_ras_client_version(&self) -> Option<String> {
        self.get_attribute_as::<String>(MS_RAS_CLIENT_VERSION_TYPE)
    }
    fn set_ms_ras_client_version(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(MS_RAS_CLIENT_VERSION_TYPE, wire_val);
    }
    fn get_ms_quarantine_ipfilter(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MS_QUARANTINE_IPFILTER_TYPE)
    }
    fn set_ms_quarantine_ipfilter(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(MS_QUARANTINE_IPFILTER_TYPE, wire_val);
    }
    fn get_ms_quarantine_session_timeout(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(MS_QUARANTINE_SESSION_TIMEOUT_TYPE)
    }
    fn set_ms_quarantine_session_timeout(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(MS_QUARANTINE_SESSION_TIMEOUT_TYPE, wire_val);
    }
    fn get_ms_user_security_identity(&self) -> Option<String> {
        self.get_attribute_as::<String>(MS_USER_SECURITY_IDENTITY_TYPE)
    }
    fn set_ms_user_security_identity(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(MS_USER_SECURITY_IDENTITY_TYPE, wire_val);
    }
    fn get_ms_identity_type(&self) -> Option<MsIdentityType> {
        self.get_attribute_as::<u32>(MS_IDENTITY_TYPE_TYPE)
            .map(MsIdentityType::from)
    }
    fn set_ms_identity_type(&mut self, value: MsIdentityType) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(MS_IDENTITY_TYPE_TYPE, wire_val);
    }
    fn get_ms_service_class(&self) -> Option<String> {
        self.get_attribute_as::<String>(MS_SERVICE_CLASS_TYPE)
    }
    fn set_ms_service_class(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(MS_SERVICE_CLASS_TYPE, wire_val);
    }
    fn get_ms_quarantine_user_class(&self) -> Option<String> {
        self.get_attribute_as::<String>(MS_QUARANTINE_USER_CLASS_TYPE)
    }
    fn set_ms_quarantine_user_class(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(MS_QUARANTINE_USER_CLASS_TYPE, wire_val);
    }
    fn get_ms_quarantine_state(&self) -> Option<MsQuarantineState> {
        self.get_attribute_as::<u32>(MS_QUARANTINE_STATE_TYPE)
            .map(MsQuarantineState::from)
    }
    fn set_ms_quarantine_state(&mut self, value: MsQuarantineState) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(MS_QUARANTINE_STATE_TYPE, wire_val);
    }
    fn get_ms_quarantine_grace_time(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(MS_QUARANTINE_GRACE_TIME_TYPE)
    }
    fn set_ms_quarantine_grace_time(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(MS_QUARANTINE_GRACE_TIME_TYPE, wire_val);
    }
    fn get_ms_network_access_server_type(&self) -> Option<MsNetworkAccessServerType> {
        self.get_attribute_as::<u32>(MS_NETWORK_ACCESS_SERVER_TYPE_TYPE)
            .map(MsNetworkAccessServerType::from)
    }
    fn set_ms_network_access_server_type(&mut self, value: MsNetworkAccessServerType) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(MS_NETWORK_ACCESS_SERVER_TYPE_TYPE, wire_val);
    }
    fn get_ms_afw_zone(&self) -> Option<MsAfwZone> {
        self.get_attribute_as::<u32>(MS_AFW_ZONE_TYPE)
            .map(MsAfwZone::from)
    }
    fn set_ms_afw_zone(&mut self, value: MsAfwZone) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(MS_AFW_ZONE_TYPE, wire_val);
    }
    fn get_ms_afw_protection_level(&self) -> Option<MsAfwProtectionLevel> {
        self.get_attribute_as::<u32>(MS_AFW_PROTECTION_LEVEL_TYPE)
            .map(MsAfwProtectionLevel::from)
    }
    fn set_ms_afw_protection_level(&mut self, value: MsAfwProtectionLevel) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(MS_AFW_PROTECTION_LEVEL_TYPE, wire_val);
    }
    fn get_ms_machine_name(&self) -> Option<String> {
        self.get_attribute_as::<String>(MS_MACHINE_NAME_TYPE)
    }
    fn set_ms_machine_name(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(MS_MACHINE_NAME_TYPE, wire_val);
    }
    fn get_ms_ipv6_filter(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MS_IPV6_FILTER_TYPE)
    }
    fn set_ms_ipv6_filter(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(MS_IPV6_FILTER_TYPE, wire_val);
    }
    fn get_ms_ipv4_remediation_servers(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MS_IPV4_REMEDIATION_SERVERS_TYPE)
    }
    fn set_ms_ipv4_remediation_servers(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(MS_IPV4_REMEDIATION_SERVERS_TYPE, wire_val);
    }
    fn get_ms_ipv6_remediation_servers(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MS_IPV6_REMEDIATION_SERVERS_TYPE)
    }
    fn set_ms_ipv6_remediation_servers(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(MS_IPV6_REMEDIATION_SERVERS_TYPE, wire_val);
    }
    fn get_ms_rnap_not_quarantine_capable(&self) -> Option<MsRnapNotQuarantineCapable> {
        self.get_attribute_as::<u32>(MS_RNAP_NOT_QUARANTINE_CAPABLE_TYPE)
            .map(MsRnapNotQuarantineCapable::from)
    }
    fn set_ms_rnap_not_quarantine_capable(&mut self, value: MsRnapNotQuarantineCapable) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(MS_RNAP_NOT_QUARANTINE_CAPABLE_TYPE, wire_val);
    }
    fn get_ms_quarantine_soh(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MS_QUARANTINE_SOH_TYPE)
    }
    fn set_ms_quarantine_soh(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(MS_QUARANTINE_SOH_TYPE, wire_val);
    }
    fn get_ms_ras_correlation(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(MS_RAS_CORRELATION_TYPE)
    }
    fn set_ms_ras_correlation(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(MS_RAS_CORRELATION_TYPE, wire_val);
    }
    fn get_ms_extended_quarantine_state(&self) -> Option<MsExtendedQuarantineState> {
        self.get_attribute_as::<u32>(MS_EXTENDED_QUARANTINE_STATE_TYPE)
            .map(MsExtendedQuarantineState::from)
    }
    fn set_ms_extended_quarantine_state(&mut self, value: MsExtendedQuarantineState) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(MS_EXTENDED_QUARANTINE_STATE_TYPE, wire_val);
    }
    fn get_ms_hcap_user_groups(&self) -> Option<String> {
        self.get_attribute_as::<String>(MS_HCAP_USER_GROUPS_TYPE)
    }
    fn set_ms_hcap_user_groups(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(MS_HCAP_USER_GROUPS_TYPE, wire_val);
    }
    fn get_ms_hcap_location_group_name(&self) -> Option<String> {
        self.get_attribute_as::<String>(MS_HCAP_LOCATION_GROUP_NAME_TYPE)
    }
    fn set_ms_hcap_location_group_name(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(MS_HCAP_LOCATION_GROUP_NAME_TYPE, wire_val);
    }
    fn get_ms_hcap_user_name(&self) -> Option<String> {
        self.get_attribute_as::<String>(MS_HCAP_USER_NAME_TYPE)
    }
    fn set_ms_hcap_user_name(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(MS_HCAP_USER_NAME_TYPE, wire_val);
    }
    fn get_ms_user_ipv4_address(&self) -> Option<Ipv4Addr> {
        self.get_attribute_as::<Ipv4Addr>(MS_USER_IPV4_ADDRESS_TYPE)
    }
    fn set_ms_user_ipv4_address(&mut self, value: Ipv4Addr) {
        let wire_val: Ipv4Addr = value.into();
        self.set_attribute_as::<Ipv4Addr>(MS_USER_IPV4_ADDRESS_TYPE, wire_val);
    }
    fn get_ms_user_ipv6_address(&self) -> Option<Ipv6Addr> {
        self.get_attribute_as::<Ipv6Addr>(MS_USER_IPV6_ADDRESS_TYPE)
    }
    fn set_ms_user_ipv6_address(&mut self, value: Ipv6Addr) {
        let wire_val: Ipv6Addr = value.into();
        self.set_attribute_as::<Ipv6Addr>(MS_USER_IPV6_ADDRESS_TYPE, wire_val);
    }
    fn get_ms_tsg_device_redirection(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(MS_TSG_DEVICE_REDIRECTION_TYPE)
    }
    fn set_ms_tsg_device_redirection(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(MS_TSG_DEVICE_REDIRECTION_TYPE, wire_val);
    }
}
