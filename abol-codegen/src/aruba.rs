use abol_core::{attribute::FromRadiusAttribute, attribute::ToRadiusAttribute, packet::Packet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;
pub const VENDOR_ARUBA: u32 = 14823u32;
pub const ARUBA_USER_ROLE_TYPE: u8 = 1u8;
pub const ARUBA_USER_VLAN_TYPE: u8 = 2u8;
pub const ARUBA_PRIV_ADMIN_USER_TYPE: u8 = 3u8;
pub const ARUBA_ADMIN_ROLE_TYPE: u8 = 4u8;
pub const ARUBA_ESSID_NAME_TYPE: u8 = 5u8;
pub const ARUBA_LOCATION_ID_TYPE: u8 = 6u8;
pub const ARUBA_PORT_IDENTIFIER_TYPE: u8 = 7u8;
pub const ARUBA_MMS_USER_TEMPLATE_TYPE: u8 = 8u8;
pub const ARUBA_NAMED_USER_VLAN_TYPE: u8 = 9u8;
pub const ARUBA_AP_GROUP_TYPE: u8 = 10u8;
pub const ARUBA_FRAMED_IPV6_ADDRESS_TYPE: u8 = 11u8;
pub const ARUBA_DEVICE_TYPE_TYPE: u8 = 12u8;
pub const ARUBA_NO_DHCP_FINGERPRINT_TYPE: u8 = 14u8;
pub const ARUBA_MDPS_DEVICE_UDID_TYPE: u8 = 15u8;
pub const ARUBA_MDPS_DEVICE_IMEI_TYPE: u8 = 16u8;
pub const ARUBA_MDPS_DEVICE_ICCID_TYPE: u8 = 17u8;
pub const ARUBA_MDPS_MAX_DEVICES_TYPE: u8 = 18u8;
pub const ARUBA_MDPS_DEVICE_NAME_TYPE: u8 = 19u8;
pub const ARUBA_MDPS_DEVICE_PRODUCT_TYPE: u8 = 20u8;
pub const ARUBA_MDPS_DEVICE_VERSION_TYPE: u8 = 21u8;
pub const ARUBA_MDPS_DEVICE_SERIAL_TYPE: u8 = 22u8;
pub const ARUBA_CPPM_ROLE_TYPE: u8 = 23u8;
pub const ARUBA_AIRGROUP_USER_NAME_TYPE: u8 = 24u8;
pub const ARUBA_AIRGROUP_SHARED_USER_TYPE: u8 = 25u8;
pub const ARUBA_AIRGROUP_SHARED_ROLE_TYPE: u8 = 26u8;
pub const ARUBA_AIRGROUP_DEVICE_TYPE_TYPE: u8 = 27u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ArubaAirgroupDeviceType {
    PersonalDevice,
    SharedDevice,
    DeletedDevice,
    Unknown(u32),
}
impl From<u32> for ArubaAirgroupDeviceType {
    fn from(v: u32) -> Self {
        match v {
            1u32 => Self::PersonalDevice,
            2u32 => Self::SharedDevice,
            3u32 => Self::DeletedDevice,
            other => Self::Unknown(other),
        }
    }
}
impl From<ArubaAirgroupDeviceType> for u32 {
    fn from(e: ArubaAirgroupDeviceType) -> Self {
        match e {
            ArubaAirgroupDeviceType::PersonalDevice => 1u32,
            ArubaAirgroupDeviceType::SharedDevice => 2u32,
            ArubaAirgroupDeviceType::DeletedDevice => 3u32,
            ArubaAirgroupDeviceType::Unknown(v) => v,
        }
    }
}
pub const ARUBA_AUTH_SURVIVABILITY_TYPE: u8 = 28u8;
pub const ARUBA_AS_USER_NAME_TYPE: u8 = 29u8;
pub const ARUBA_AS_CREDENTIAL_HASH_TYPE: u8 = 30u8;
pub const ARUBA_WORKSPACE_APP_NAME_TYPE: u8 = 31u8;
pub const ARUBA_MDPS_PROVISIONING_SETTINGS_TYPE: u8 = 32u8;
pub const ARUBA_MDPS_DEVICE_PROFILE_TYPE: u8 = 33u8;
pub const ARUBA_AP_IP_ADDRESS_TYPE: u8 = 34u8;
pub const ARUBA_AIRGROUP_SHARED_GROUP_TYPE: u8 = 35u8;
pub const ARUBA_USER_GROUP_TYPE: u8 = 36u8;
pub const ARUBA_NETWORK_SSO_TOKEN_TYPE: u8 = 37u8;
pub const ARUBA_AIRGROUP_VERSION_TYPE: u8 = 38u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ArubaAirgroupVersion {
    AirGroupV1,
    AirGroupV2,
    Unknown(u32),
}
impl From<u32> for ArubaAirgroupVersion {
    fn from(v: u32) -> Self {
        match v {
            1u32 => Self::AirGroupV1,
            2u32 => Self::AirGroupV2,
            other => Self::Unknown(other),
        }
    }
}
impl From<ArubaAirgroupVersion> for u32 {
    fn from(e: ArubaAirgroupVersion) -> Self {
        match e {
            ArubaAirgroupVersion::AirGroupV1 => 1u32,
            ArubaAirgroupVersion::AirGroupV2 => 2u32,
            ArubaAirgroupVersion::Unknown(v) => v,
        }
    }
}
pub const ARUBA_AUTH_SURVMETHOD_TYPE: u8 = 39u8;
pub const ARUBA_PORT_BOUNCE_HOST_TYPE: u8 = 40u8;
pub const ARUBA_CALEA_SERVER_IP_TYPE: u8 = 41u8;
pub const ARUBA_ADMIN_PATH_TYPE: u8 = 42u8;
pub const ARUBA_CAPTIVE_PORTAL_URL_TYPE: u8 = 43u8;
pub const ARUBA_MPSK_PASSPHRASE_TYPE: u8 = 44u8;
pub const ARUBA_ACL_SERVER_QUERY_INFO_TYPE: u8 = 45u8;
pub const ARUBA_COMMAND_STRING_TYPE: u8 = 46u8;
pub const ARUBA_NETWORK_PROFILE_TYPE: u8 = 47u8;
pub const ARUBA_ADMIN_DEVICE_GROUP_TYPE: u8 = 48u8;
pub const ARUBA_POE_PRIORITY_TYPE: u8 = 49u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ArubaPoePriority {
    Critical,
    High,
    Low,
    Unknown(u32),
}
impl From<u32> for ArubaPoePriority {
    fn from(v: u32) -> Self {
        match v {
            0u32 => Self::Critical,
            1u32 => Self::High,
            2u32 => Self::Low,
            other => Self::Unknown(other),
        }
    }
}
impl From<ArubaPoePriority> for u32 {
    fn from(e: ArubaPoePriority) -> Self {
        match e {
            ArubaPoePriority::Critical => 0u32,
            ArubaPoePriority::High => 1u32,
            ArubaPoePriority::Low => 2u32,
            ArubaPoePriority::Unknown(v) => v,
        }
    }
}
pub const ARUBA_PORT_AUTH_MODE_TYPE: u8 = 50u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ArubaPortAuthMode {
    InfrastructureMode,
    ClientMode,
    Unknown(u32),
}
impl From<u32> for ArubaPortAuthMode {
    fn from(v: u32) -> Self {
        match v {
            1u32 => Self::InfrastructureMode,
            2u32 => Self::ClientMode,
            other => Self::Unknown(other),
        }
    }
}
impl From<ArubaPortAuthMode> for u32 {
    fn from(e: ArubaPortAuthMode) -> Self {
        match e {
            ArubaPortAuthMode::InfrastructureMode => 1u32,
            ArubaPortAuthMode::ClientMode => 2u32,
            ArubaPortAuthMode::Unknown(v) => v,
        }
    }
}
pub const ARUBA_NAS_FILTER_RULE_TYPE: u8 = 51u8;
pub const ARUBA_QOS_TRUST_MODE_TYPE: u8 = 52u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ArubaQosTrustMode {
    Dscp,
    QoS,
    None,
    Unknown(u32),
}
impl From<u32> for ArubaQosTrustMode {
    fn from(v: u32) -> Self {
        match v {
            0u32 => Self::Dscp,
            1u32 => Self::QoS,
            2u32 => Self::None,
            other => Self::Unknown(other),
        }
    }
}
impl From<ArubaQosTrustMode> for u32 {
    fn from(e: ArubaQosTrustMode) -> Self {
        match e {
            ArubaQosTrustMode::Dscp => 0u32,
            ArubaQosTrustMode::QoS => 1u32,
            ArubaQosTrustMode::None => 2u32,
            ArubaQosTrustMode::Unknown(v) => v,
        }
    }
}
pub const ARUBA_UBT_GATEWAY_ROLE_TYPE: u8 = 53u8;
pub const ARUBA_GATEWAY_ZONE_TYPE: u8 = 54u8;
pub trait ArubaExt {
    fn get_aruba_user_role(&self) -> Option<String>;
    fn set_aruba_user_role(&mut self, value: impl Into<String>);
    fn get_aruba_user_vlan(&self) -> Option<u32>;
    fn set_aruba_user_vlan(&mut self, value: u32);
    fn get_aruba_priv_admin_user(&self) -> Option<u32>;
    fn set_aruba_priv_admin_user(&mut self, value: u32);
    fn get_aruba_admin_role(&self) -> Option<String>;
    fn set_aruba_admin_role(&mut self, value: impl Into<String>);
    fn get_aruba_essid_name(&self) -> Option<String>;
    fn set_aruba_essid_name(&mut self, value: impl Into<String>);
    fn get_aruba_location_id(&self) -> Option<String>;
    fn set_aruba_location_id(&mut self, value: impl Into<String>);
    fn get_aruba_port_identifier(&self) -> Option<String>;
    fn set_aruba_port_identifier(&mut self, value: impl Into<String>);
    fn get_aruba_mms_user_template(&self) -> Option<String>;
    fn set_aruba_mms_user_template(&mut self, value: impl Into<String>);
    fn get_aruba_named_user_vlan(&self) -> Option<String>;
    fn set_aruba_named_user_vlan(&mut self, value: impl Into<String>);
    fn get_aruba_ap_group(&self) -> Option<String>;
    fn set_aruba_ap_group(&mut self, value: impl Into<String>);
    fn get_aruba_framed_ipv6_address(&self) -> Option<String>;
    fn set_aruba_framed_ipv6_address(&mut self, value: impl Into<String>);
    fn get_aruba_device_type(&self) -> Option<String>;
    fn set_aruba_device_type(&mut self, value: impl Into<String>);
    fn get_aruba_no_dhcp_fingerprint(&self) -> Option<u32>;
    fn set_aruba_no_dhcp_fingerprint(&mut self, value: u32);
    fn get_aruba_mdps_device_udid(&self) -> Option<String>;
    fn set_aruba_mdps_device_udid(&mut self, value: impl Into<String>);
    fn get_aruba_mdps_device_imei(&self) -> Option<String>;
    fn set_aruba_mdps_device_imei(&mut self, value: impl Into<String>);
    fn get_aruba_mdps_device_iccid(&self) -> Option<String>;
    fn set_aruba_mdps_device_iccid(&mut self, value: impl Into<String>);
    fn get_aruba_mdps_max_devices(&self) -> Option<u32>;
    fn set_aruba_mdps_max_devices(&mut self, value: u32);
    fn get_aruba_mdps_device_name(&self) -> Option<String>;
    fn set_aruba_mdps_device_name(&mut self, value: impl Into<String>);
    fn get_aruba_mdps_device_product(&self) -> Option<String>;
    fn set_aruba_mdps_device_product(&mut self, value: impl Into<String>);
    fn get_aruba_mdps_device_version(&self) -> Option<String>;
    fn set_aruba_mdps_device_version(&mut self, value: impl Into<String>);
    fn get_aruba_mdps_device_serial(&self) -> Option<String>;
    fn set_aruba_mdps_device_serial(&mut self, value: impl Into<String>);
    fn get_aruba_cppm_role(&self) -> Option<String>;
    fn set_aruba_cppm_role(&mut self, value: impl Into<String>);
    fn get_aruba_airgroup_user_name(&self) -> Option<String>;
    fn set_aruba_airgroup_user_name(&mut self, value: impl Into<String>);
    fn get_aruba_airgroup_shared_user(&self) -> Option<String>;
    fn set_aruba_airgroup_shared_user(&mut self, value: impl Into<String>);
    fn get_aruba_airgroup_shared_role(&self) -> Option<String>;
    fn set_aruba_airgroup_shared_role(&mut self, value: impl Into<String>);
    fn get_aruba_airgroup_device_type(&self) -> Option<ArubaAirgroupDeviceType>;
    fn set_aruba_airgroup_device_type(&mut self, value: ArubaAirgroupDeviceType);
    fn get_aruba_auth_survivability(&self) -> Option<String>;
    fn set_aruba_auth_survivability(&mut self, value: impl Into<String>);
    fn get_aruba_as_user_name(&self) -> Option<String>;
    fn set_aruba_as_user_name(&mut self, value: impl Into<String>);
    fn get_aruba_as_credential_hash(&self) -> Option<String>;
    fn set_aruba_as_credential_hash(&mut self, value: impl Into<String>);
    fn get_aruba_workspace_app_name(&self) -> Option<String>;
    fn set_aruba_workspace_app_name(&mut self, value: impl Into<String>);
    fn get_aruba_mdps_provisioning_settings(&self) -> Option<String>;
    fn set_aruba_mdps_provisioning_settings(&mut self, value: impl Into<String>);
    fn get_aruba_mdps_device_profile(&self) -> Option<String>;
    fn set_aruba_mdps_device_profile(&mut self, value: impl Into<String>);
    fn get_aruba_ap_ip_address(&self) -> Option<Ipv4Addr>;
    fn set_aruba_ap_ip_address(&mut self, value: Ipv4Addr);
    fn get_aruba_airgroup_shared_group(&self) -> Option<String>;
    fn set_aruba_airgroup_shared_group(&mut self, value: impl Into<String>);
    fn get_aruba_user_group(&self) -> Option<String>;
    fn set_aruba_user_group(&mut self, value: impl Into<String>);
    fn get_aruba_network_sso_token(&self) -> Option<String>;
    fn set_aruba_network_sso_token(&mut self, value: impl Into<String>);
    fn get_aruba_airgroup_version(&self) -> Option<ArubaAirgroupVersion>;
    fn set_aruba_airgroup_version(&mut self, value: ArubaAirgroupVersion);
    fn get_aruba_auth_survmethod(&self) -> Option<u32>;
    fn set_aruba_auth_survmethod(&mut self, value: u32);
    fn get_aruba_port_bounce_host(&self) -> Option<u32>;
    fn set_aruba_port_bounce_host(&mut self, value: u32);
    fn get_aruba_calea_server_ip(&self) -> Option<Ipv4Addr>;
    fn set_aruba_calea_server_ip(&mut self, value: Ipv4Addr);
    fn get_aruba_admin_path(&self) -> Option<String>;
    fn set_aruba_admin_path(&mut self, value: impl Into<String>);
    fn get_aruba_captive_portal_url(&self) -> Option<String>;
    fn set_aruba_captive_portal_url(&mut self, value: impl Into<String>);
    fn get_aruba_mpsk_passphrase(&self) -> Option<Vec<u8>>;
    fn set_aruba_mpsk_passphrase(&mut self, value: impl Into<Vec<u8>>);
    fn get_aruba_acl_server_query_info(&self) -> Option<String>;
    fn set_aruba_acl_server_query_info(&mut self, value: impl Into<String>);
    fn get_aruba_command_string(&self) -> Option<String>;
    fn set_aruba_command_string(&mut self, value: impl Into<String>);
    fn get_aruba_network_profile(&self) -> Option<String>;
    fn set_aruba_network_profile(&mut self, value: impl Into<String>);
    fn get_aruba_admin_device_group(&self) -> Option<String>;
    fn set_aruba_admin_device_group(&mut self, value: impl Into<String>);
    fn get_aruba_poe_priority(&self) -> Option<ArubaPoePriority>;
    fn set_aruba_poe_priority(&mut self, value: ArubaPoePriority);
    fn get_aruba_port_auth_mode(&self) -> Option<ArubaPortAuthMode>;
    fn set_aruba_port_auth_mode(&mut self, value: ArubaPortAuthMode);
    fn get_aruba_nas_filter_rule(&self) -> Option<String>;
    fn set_aruba_nas_filter_rule(&mut self, value: impl Into<String>);
    fn get_aruba_qos_trust_mode(&self) -> Option<ArubaQosTrustMode>;
    fn set_aruba_qos_trust_mode(&mut self, value: ArubaQosTrustMode);
    fn get_aruba_ubt_gateway_role(&self) -> Option<String>;
    fn set_aruba_ubt_gateway_role(&mut self, value: impl Into<String>);
    fn get_aruba_gateway_zone(&self) -> Option<String>;
    fn set_aruba_gateway_zone(&mut self, value: impl Into<String>);
}
impl ArubaExt for Packet {
    fn get_aruba_user_role(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_USER_ROLE_TYPE)
    }
    fn set_aruba_user_role(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_USER_ROLE_TYPE, wire_val);
    }
    fn get_aruba_user_vlan(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(ARUBA_USER_VLAN_TYPE)
    }
    fn set_aruba_user_vlan(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ARUBA_USER_VLAN_TYPE, wire_val);
    }
    fn get_aruba_priv_admin_user(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(ARUBA_PRIV_ADMIN_USER_TYPE)
    }
    fn set_aruba_priv_admin_user(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ARUBA_PRIV_ADMIN_USER_TYPE, wire_val);
    }
    fn get_aruba_admin_role(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_ADMIN_ROLE_TYPE)
    }
    fn set_aruba_admin_role(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_ADMIN_ROLE_TYPE, wire_val);
    }
    fn get_aruba_essid_name(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_ESSID_NAME_TYPE)
    }
    fn set_aruba_essid_name(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_ESSID_NAME_TYPE, wire_val);
    }
    fn get_aruba_location_id(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_LOCATION_ID_TYPE)
    }
    fn set_aruba_location_id(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_LOCATION_ID_TYPE, wire_val);
    }
    fn get_aruba_port_identifier(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_PORT_IDENTIFIER_TYPE)
    }
    fn set_aruba_port_identifier(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_PORT_IDENTIFIER_TYPE, wire_val);
    }
    fn get_aruba_mms_user_template(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_MMS_USER_TEMPLATE_TYPE)
    }
    fn set_aruba_mms_user_template(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_MMS_USER_TEMPLATE_TYPE, wire_val);
    }
    fn get_aruba_named_user_vlan(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_NAMED_USER_VLAN_TYPE)
    }
    fn set_aruba_named_user_vlan(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_NAMED_USER_VLAN_TYPE, wire_val);
    }
    fn get_aruba_ap_group(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_AP_GROUP_TYPE)
    }
    fn set_aruba_ap_group(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_AP_GROUP_TYPE, wire_val);
    }
    fn get_aruba_framed_ipv6_address(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_FRAMED_IPV6_ADDRESS_TYPE)
    }
    fn set_aruba_framed_ipv6_address(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_FRAMED_IPV6_ADDRESS_TYPE, wire_val);
    }
    fn get_aruba_device_type(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_DEVICE_TYPE_TYPE)
    }
    fn set_aruba_device_type(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_DEVICE_TYPE_TYPE, wire_val);
    }
    fn get_aruba_no_dhcp_fingerprint(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(ARUBA_NO_DHCP_FINGERPRINT_TYPE)
    }
    fn set_aruba_no_dhcp_fingerprint(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ARUBA_NO_DHCP_FINGERPRINT_TYPE, wire_val);
    }
    fn get_aruba_mdps_device_udid(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_MDPS_DEVICE_UDID_TYPE)
    }
    fn set_aruba_mdps_device_udid(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_MDPS_DEVICE_UDID_TYPE, wire_val);
    }
    fn get_aruba_mdps_device_imei(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_MDPS_DEVICE_IMEI_TYPE)
    }
    fn set_aruba_mdps_device_imei(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_MDPS_DEVICE_IMEI_TYPE, wire_val);
    }
    fn get_aruba_mdps_device_iccid(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_MDPS_DEVICE_ICCID_TYPE)
    }
    fn set_aruba_mdps_device_iccid(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_MDPS_DEVICE_ICCID_TYPE, wire_val);
    }
    fn get_aruba_mdps_max_devices(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(ARUBA_MDPS_MAX_DEVICES_TYPE)
    }
    fn set_aruba_mdps_max_devices(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ARUBA_MDPS_MAX_DEVICES_TYPE, wire_val);
    }
    fn get_aruba_mdps_device_name(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_MDPS_DEVICE_NAME_TYPE)
    }
    fn set_aruba_mdps_device_name(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_MDPS_DEVICE_NAME_TYPE, wire_val);
    }
    fn get_aruba_mdps_device_product(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_MDPS_DEVICE_PRODUCT_TYPE)
    }
    fn set_aruba_mdps_device_product(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_MDPS_DEVICE_PRODUCT_TYPE, wire_val);
    }
    fn get_aruba_mdps_device_version(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_MDPS_DEVICE_VERSION_TYPE)
    }
    fn set_aruba_mdps_device_version(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_MDPS_DEVICE_VERSION_TYPE, wire_val);
    }
    fn get_aruba_mdps_device_serial(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_MDPS_DEVICE_SERIAL_TYPE)
    }
    fn set_aruba_mdps_device_serial(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_MDPS_DEVICE_SERIAL_TYPE, wire_val);
    }
    fn get_aruba_cppm_role(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_CPPM_ROLE_TYPE)
    }
    fn set_aruba_cppm_role(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_CPPM_ROLE_TYPE, wire_val);
    }
    fn get_aruba_airgroup_user_name(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_AIRGROUP_USER_NAME_TYPE)
    }
    fn set_aruba_airgroup_user_name(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_AIRGROUP_USER_NAME_TYPE, wire_val);
    }
    fn get_aruba_airgroup_shared_user(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_AIRGROUP_SHARED_USER_TYPE)
    }
    fn set_aruba_airgroup_shared_user(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_AIRGROUP_SHARED_USER_TYPE, wire_val);
    }
    fn get_aruba_airgroup_shared_role(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_AIRGROUP_SHARED_ROLE_TYPE)
    }
    fn set_aruba_airgroup_shared_role(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_AIRGROUP_SHARED_ROLE_TYPE, wire_val);
    }
    fn get_aruba_airgroup_device_type(&self) -> Option<ArubaAirgroupDeviceType> {
        self.get_attribute_as::<u32>(ARUBA_AIRGROUP_DEVICE_TYPE_TYPE)
            .map(ArubaAirgroupDeviceType::from)
    }
    fn set_aruba_airgroup_device_type(&mut self, value: ArubaAirgroupDeviceType) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ARUBA_AIRGROUP_DEVICE_TYPE_TYPE, wire_val);
    }
    fn get_aruba_auth_survivability(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_AUTH_SURVIVABILITY_TYPE)
    }
    fn set_aruba_auth_survivability(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_AUTH_SURVIVABILITY_TYPE, wire_val);
    }
    fn get_aruba_as_user_name(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_AS_USER_NAME_TYPE)
    }
    fn set_aruba_as_user_name(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_AS_USER_NAME_TYPE, wire_val);
    }
    fn get_aruba_as_credential_hash(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_AS_CREDENTIAL_HASH_TYPE)
    }
    fn set_aruba_as_credential_hash(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_AS_CREDENTIAL_HASH_TYPE, wire_val);
    }
    fn get_aruba_workspace_app_name(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_WORKSPACE_APP_NAME_TYPE)
    }
    fn set_aruba_workspace_app_name(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_WORKSPACE_APP_NAME_TYPE, wire_val);
    }
    fn get_aruba_mdps_provisioning_settings(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_MDPS_PROVISIONING_SETTINGS_TYPE)
    }
    fn set_aruba_mdps_provisioning_settings(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_MDPS_PROVISIONING_SETTINGS_TYPE, wire_val);
    }
    fn get_aruba_mdps_device_profile(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_MDPS_DEVICE_PROFILE_TYPE)
    }
    fn set_aruba_mdps_device_profile(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_MDPS_DEVICE_PROFILE_TYPE, wire_val);
    }
    fn get_aruba_ap_ip_address(&self) -> Option<Ipv4Addr> {
        self.get_attribute_as::<Ipv4Addr>(ARUBA_AP_IP_ADDRESS_TYPE)
    }
    fn set_aruba_ap_ip_address(&mut self, value: Ipv4Addr) {
        let wire_val: Ipv4Addr = value.into();
        self.set_attribute_as::<Ipv4Addr>(ARUBA_AP_IP_ADDRESS_TYPE, wire_val);
    }
    fn get_aruba_airgroup_shared_group(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_AIRGROUP_SHARED_GROUP_TYPE)
    }
    fn set_aruba_airgroup_shared_group(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_AIRGROUP_SHARED_GROUP_TYPE, wire_val);
    }
    fn get_aruba_user_group(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_USER_GROUP_TYPE)
    }
    fn set_aruba_user_group(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_USER_GROUP_TYPE, wire_val);
    }
    fn get_aruba_network_sso_token(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_NETWORK_SSO_TOKEN_TYPE)
    }
    fn set_aruba_network_sso_token(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_NETWORK_SSO_TOKEN_TYPE, wire_val);
    }
    fn get_aruba_airgroup_version(&self) -> Option<ArubaAirgroupVersion> {
        self.get_attribute_as::<u32>(ARUBA_AIRGROUP_VERSION_TYPE)
            .map(ArubaAirgroupVersion::from)
    }
    fn set_aruba_airgroup_version(&mut self, value: ArubaAirgroupVersion) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ARUBA_AIRGROUP_VERSION_TYPE, wire_val);
    }
    fn get_aruba_auth_survmethod(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(ARUBA_AUTH_SURVMETHOD_TYPE)
    }
    fn set_aruba_auth_survmethod(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ARUBA_AUTH_SURVMETHOD_TYPE, wire_val);
    }
    fn get_aruba_port_bounce_host(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(ARUBA_PORT_BOUNCE_HOST_TYPE)
    }
    fn set_aruba_port_bounce_host(&mut self, value: u32) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ARUBA_PORT_BOUNCE_HOST_TYPE, wire_val);
    }
    fn get_aruba_calea_server_ip(&self) -> Option<Ipv4Addr> {
        self.get_attribute_as::<Ipv4Addr>(ARUBA_CALEA_SERVER_IP_TYPE)
    }
    fn set_aruba_calea_server_ip(&mut self, value: Ipv4Addr) {
        let wire_val: Ipv4Addr = value.into();
        self.set_attribute_as::<Ipv4Addr>(ARUBA_CALEA_SERVER_IP_TYPE, wire_val);
    }
    fn get_aruba_admin_path(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_ADMIN_PATH_TYPE)
    }
    fn set_aruba_admin_path(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_ADMIN_PATH_TYPE, wire_val);
    }
    fn get_aruba_captive_portal_url(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_CAPTIVE_PORTAL_URL_TYPE)
    }
    fn set_aruba_captive_portal_url(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_CAPTIVE_PORTAL_URL_TYPE, wire_val);
    }
    fn get_aruba_mpsk_passphrase(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(ARUBA_MPSK_PASSPHRASE_TYPE)
    }
    fn set_aruba_mpsk_passphrase(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(ARUBA_MPSK_PASSPHRASE_TYPE, wire_val);
    }
    fn get_aruba_acl_server_query_info(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_ACL_SERVER_QUERY_INFO_TYPE)
    }
    fn set_aruba_acl_server_query_info(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_ACL_SERVER_QUERY_INFO_TYPE, wire_val);
    }
    fn get_aruba_command_string(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_COMMAND_STRING_TYPE)
    }
    fn set_aruba_command_string(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_COMMAND_STRING_TYPE, wire_val);
    }
    fn get_aruba_network_profile(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_NETWORK_PROFILE_TYPE)
    }
    fn set_aruba_network_profile(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_NETWORK_PROFILE_TYPE, wire_val);
    }
    fn get_aruba_admin_device_group(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_ADMIN_DEVICE_GROUP_TYPE)
    }
    fn set_aruba_admin_device_group(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_ADMIN_DEVICE_GROUP_TYPE, wire_val);
    }
    fn get_aruba_poe_priority(&self) -> Option<ArubaPoePriority> {
        self.get_attribute_as::<u32>(ARUBA_POE_PRIORITY_TYPE)
            .map(ArubaPoePriority::from)
    }
    fn set_aruba_poe_priority(&mut self, value: ArubaPoePriority) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ARUBA_POE_PRIORITY_TYPE, wire_val);
    }
    fn get_aruba_port_auth_mode(&self) -> Option<ArubaPortAuthMode> {
        self.get_attribute_as::<u32>(ARUBA_PORT_AUTH_MODE_TYPE)
            .map(ArubaPortAuthMode::from)
    }
    fn set_aruba_port_auth_mode(&mut self, value: ArubaPortAuthMode) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ARUBA_PORT_AUTH_MODE_TYPE, wire_val);
    }
    fn get_aruba_nas_filter_rule(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_NAS_FILTER_RULE_TYPE)
    }
    fn set_aruba_nas_filter_rule(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_NAS_FILTER_RULE_TYPE, wire_val);
    }
    fn get_aruba_qos_trust_mode(&self) -> Option<ArubaQosTrustMode> {
        self.get_attribute_as::<u32>(ARUBA_QOS_TRUST_MODE_TYPE)
            .map(ArubaQosTrustMode::from)
    }
    fn set_aruba_qos_trust_mode(&mut self, value: ArubaQosTrustMode) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ARUBA_QOS_TRUST_MODE_TYPE, wire_val);
    }
    fn get_aruba_ubt_gateway_role(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_UBT_GATEWAY_ROLE_TYPE)
    }
    fn set_aruba_ubt_gateway_role(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_UBT_GATEWAY_ROLE_TYPE, wire_val);
    }
    fn get_aruba_gateway_zone(&self) -> Option<String> {
        self.get_attribute_as::<String>(ARUBA_GATEWAY_ZONE_TYPE)
    }
    fn set_aruba_gateway_zone(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(ARUBA_GATEWAY_ZONE_TYPE, wire_val);
    }
}
