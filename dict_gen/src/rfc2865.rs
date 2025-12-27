#![allow(unused_imports)]
#![allow(dead_code)]
use radius_core::packet::Packet;
use std::net::{Ipv4Addr, Ipv6Addr};
pub const USER_NAME_TYPE: u8 = 1u8;
pub const USER_PASSWORD_TYPE: u8 = 2u8;
pub const CHAP_PASSWORD_TYPE: u8 = 3u8;
pub const NAS_IP_ADDRESS_TYPE: u8 = 4u8;
pub const NAS_PORT_TYPE: u8 = 5u8;
pub const SERVICE_TYPE_TYPE: u8 = 6u8;
pub const SERVICE_TYPE_LOGIN_USER: u64 = 1u64;
pub const SERVICE_TYPE_FRAMED_USER: u64 = 2u64;
pub const SERVICE_TYPE_CALLBACK_LOGIN_USER: u64 = 3u64;
pub const SERVICE_TYPE_CALLBACK_FRAMED_USER: u64 = 4u64;
pub const SERVICE_TYPE_OUTBOUND_USER: u64 = 5u64;
pub const SERVICE_TYPE_ADMINISTRATIVE_USER: u64 = 6u64;
pub const SERVICE_TYPE_NAS_PROMPT_USER: u64 = 7u64;
pub const SERVICE_TYPE_AUTHENTICATE_ONLY: u64 = 8u64;
pub const SERVICE_TYPE_CALLBACK_NAS_PROMPT: u64 = 9u64;
pub const SERVICE_TYPE_CALL_CHECK: u64 = 10u64;
pub const SERVICE_TYPE_CALLBACK_ADMINISTRATIVE: u64 = 11u64;
pub const FRAMED_PROTOCOL_TYPE: u8 = 7u8;
pub const FRAMED_PROTOCOL_PPP: u64 = 1u64;
pub const FRAMED_PROTOCOL_SLIP: u64 = 2u64;
pub const FRAMED_PROTOCOL_ARAP: u64 = 3u64;
pub const FRAMED_PROTOCOL_GANDALF_SLML: u64 = 4u64;
pub const FRAMED_PROTOCOL_XYLOGICS_IPX_SLIP: u64 = 5u64;
pub const FRAMED_PROTOCOL_X_75_SYNCHRONOUS: u64 = 6u64;
pub const FRAMED_IP_ADDRESS_TYPE: u8 = 8u8;
pub const FRAMED_IP_NETMASK_TYPE: u8 = 9u8;
pub const FRAMED_ROUTING_TYPE: u8 = 10u8;
pub const FRAMED_ROUTING_NONE: u64 = 0u64;
pub const FRAMED_ROUTING_BROADCAST: u64 = 1u64;
pub const FRAMED_ROUTING_LISTEN: u64 = 2u64;
pub const FRAMED_ROUTING_BROADCAST_LISTEN: u64 = 3u64;
pub const FILTER_ID_TYPE: u8 = 11u8;
pub const FRAMED_MTU_TYPE: u8 = 12u8;
pub const FRAMED_COMPRESSION_TYPE: u8 = 13u8;
pub const FRAMED_COMPRESSION_NONE: u64 = 0u64;
pub const FRAMED_COMPRESSION_VAN_JACOBSON_TCP_IP: u64 = 1u64;
pub const FRAMED_COMPRESSION_IPX_HEADER_COMPRESSION: u64 = 2u64;
pub const FRAMED_COMPRESSION_STAC_LZS: u64 = 3u64;
pub const LOGIN_IP_HOST_TYPE: u8 = 14u8;
pub const LOGIN_SERVICE_TYPE: u8 = 15u8;
pub const LOGIN_SERVICE_TELNET: u64 = 0u64;
pub const LOGIN_SERVICE_RLOGIN: u64 = 1u64;
pub const LOGIN_SERVICE_TCP_CLEAR: u64 = 2u64;
pub const LOGIN_SERVICE_PORT_MASTER: u64 = 3u64;
pub const LOGIN_SERVICE_LAT: u64 = 4u64;
pub const LOGIN_SERVICE_X25_PAD: u64 = 5u64;
pub const LOGIN_SERVICE_X25_T3POS: u64 = 6u64;
pub const LOGIN_SERVICE_TCP_CLEAR_QUIET: u64 = 8u64;
pub const LOGIN_TCP_PORT_TYPE: u8 = 16u8;
pub const LOGIN_TCP_PORT_TELNET: u64 = 23u64;
pub const LOGIN_TCP_PORT_RLOGIN: u64 = 513u64;
pub const LOGIN_TCP_PORT_RSH: u64 = 514u64;
pub const REPLY_MESSAGE_TYPE: u8 = 18u8;
pub const CALLBACK_NUMBER_TYPE: u8 = 19u8;
pub const CALLBACK_ID_TYPE: u8 = 20u8;
pub const FRAMED_ROUTE_TYPE: u8 = 22u8;
pub const FRAMED_IPX_NETWORK_TYPE: u8 = 23u8;
pub const STATE_TYPE: u8 = 24u8;
pub const CLASS_TYPE: u8 = 25u8;
pub const VENDOR_SPECIFIC_TYPE: u8 = 26u8;
pub const SESSION_TIMEOUT_TYPE: u8 = 27u8;
pub const IDLE_TIMEOUT_TYPE: u8 = 28u8;
pub const TERMINATION_ACTION_TYPE: u8 = 29u8;
pub const TERMINATION_ACTION_DEFAULT: u64 = 0u64;
pub const TERMINATION_ACTION_RADIUS_REQUEST: u64 = 1u64;
pub const CALLED_STATION_ID_TYPE: u8 = 30u8;
pub const CALLING_STATION_ID_TYPE: u8 = 31u8;
pub const NAS_IDENTIFIER_TYPE: u8 = 32u8;
pub const PROXY_STATE_TYPE: u8 = 33u8;
pub const LOGIN_LAT_SERVICE_TYPE: u8 = 34u8;
pub const LOGIN_LAT_NODE_TYPE: u8 = 35u8;
pub const LOGIN_LAT_GROUP_TYPE: u8 = 36u8;
pub const FRAMED_APPLE_TALK_LINK_TYPE: u8 = 37u8;
pub const FRAMED_APPLE_TALK_NETWORK_TYPE: u8 = 38u8;
pub const FRAMED_APPLE_TALK_ZONE_TYPE: u8 = 39u8;
pub const CHAP_CHALLENGE_TYPE: u8 = 60u8;
pub const NAS_PORT_TYPE_TYPE: u8 = 61u8;
pub const NAS_PORT_TYPE_ASYNC: u64 = 0u64;
pub const NAS_PORT_TYPE_SYNC: u64 = 1u64;
pub const NAS_PORT_TYPE_ISDN: u64 = 2u64;
pub const NAS_PORT_TYPE_ISDN_V120: u64 = 3u64;
pub const NAS_PORT_TYPE_ISDN_V110: u64 = 4u64;
pub const NAS_PORT_TYPE_VIRTUAL: u64 = 5u64;
pub const NAS_PORT_TYPE_PIAFS: u64 = 6u64;
pub const NAS_PORT_TYPE_HDLC_CLEAR_CHANNEL: u64 = 7u64;
pub const NAS_PORT_TYPE_X_25: u64 = 8u64;
pub const NAS_PORT_TYPE_X_75: u64 = 9u64;
pub const NAS_PORT_TYPE_G_3_FAX: u64 = 10u64;
pub const NAS_PORT_TYPE_SDSL: u64 = 11u64;
pub const NAS_PORT_TYPE_ADSL_CAP: u64 = 12u64;
pub const NAS_PORT_TYPE_ADSL_DMT: u64 = 13u64;
pub const NAS_PORT_TYPE_IDSL: u64 = 14u64;
pub const NAS_PORT_TYPE_ETHERNET: u64 = 15u64;
pub const NAS_PORT_TYPE_X_DSL: u64 = 16u64;
pub const NAS_PORT_TYPE_CABLE: u64 = 17u64;
pub const NAS_PORT_TYPE_WIRELESS_OTHER: u64 = 18u64;
pub const NAS_PORT_TYPE_WIRELESS_802_11: u64 = 19u64;
pub const PORT_LIMIT_TYPE: u8 = 62u8;
pub const LOGIN_LAT_PORT_TYPE: u8 = 63u8;
pub trait Rfc2865Ext {
    fn get_user_name(&self) -> Option<&[u8]>;
    fn set_user_name(&mut self, value: &[u8]);
    fn get_user_password(&self) -> Option<&[u8]>;
    fn set_user_password(&mut self, value: &[u8]);
    fn get_chap_password(&self) -> Option<&[u8]>;
    fn set_chap_password(&mut self, value: &[u8]);
    fn get_nas_ip_address(&self) -> Option<Ipv4Addr>;
    fn set_nas_ip_address(&mut self, value: Ipv4Addr);
    fn get_nas_port(&self) -> Option<u32>;
    fn set_nas_port(&mut self, value: u32);
    fn get_service_type(&self) -> Option<u32>;
    fn set_service_type(&mut self, value: u32);
    fn get_framed_protocol(&self) -> Option<u32>;
    fn set_framed_protocol(&mut self, value: u32);
    fn get_framed_ip_address(&self) -> Option<Ipv4Addr>;
    fn set_framed_ip_address(&mut self, value: Ipv4Addr);
    fn get_framed_ip_netmask(&self) -> Option<Ipv4Addr>;
    fn set_framed_ip_netmask(&mut self, value: Ipv4Addr);
    fn get_framed_routing(&self) -> Option<u32>;
    fn set_framed_routing(&mut self, value: u32);
    fn get_filter_id(&self) -> Option<&[u8]>;
    fn set_filter_id(&mut self, value: &[u8]);
    fn get_framed_mtu(&self) -> Option<u32>;
    fn set_framed_mtu(&mut self, value: u32);
    fn get_framed_compression(&self) -> Option<u32>;
    fn set_framed_compression(&mut self, value: u32);
    fn get_login_ip_host(&self) -> Option<Ipv4Addr>;
    fn set_login_ip_host(&mut self, value: Ipv4Addr);
    fn get_login_service(&self) -> Option<u32>;
    fn set_login_service(&mut self, value: u32);
    fn get_login_tcp_port(&self) -> Option<u32>;
    fn set_login_tcp_port(&mut self, value: u32);
    fn get_reply_message(&self) -> Option<&[u8]>;
    fn set_reply_message(&mut self, value: &[u8]);
    fn get_callback_number(&self) -> Option<&[u8]>;
    fn set_callback_number(&mut self, value: &[u8]);
    fn get_callback_id(&self) -> Option<&[u8]>;
    fn set_callback_id(&mut self, value: &[u8]);
    fn get_framed_route(&self) -> Option<&[u8]>;
    fn set_framed_route(&mut self, value: &[u8]);
    fn get_framed_ipx_network(&self) -> Option<Ipv4Addr>;
    fn set_framed_ipx_network(&mut self, value: Ipv4Addr);
    fn get_state(&self) -> Option<&[u8]>;
    fn set_state(&mut self, value: &[u8]);
    fn get_class(&self) -> Option<&[u8]>;
    fn set_class(&mut self, value: &[u8]);
    fn get_session_timeout(&self) -> Option<u32>;
    fn set_session_timeout(&mut self, value: u32);
    fn get_idle_timeout(&self) -> Option<u32>;
    fn set_idle_timeout(&mut self, value: u32);
    fn get_termination_action(&self) -> Option<u32>;
    fn set_termination_action(&mut self, value: u32);
    fn get_called_station_id(&self) -> Option<&[u8]>;
    fn set_called_station_id(&mut self, value: &[u8]);
    fn get_calling_station_id(&self) -> Option<&[u8]>;
    fn set_calling_station_id(&mut self, value: &[u8]);
    fn get_nas_identifier(&self) -> Option<&[u8]>;
    fn set_nas_identifier(&mut self, value: &[u8]);
    fn get_proxy_state(&self) -> Option<&[u8]>;
    fn set_proxy_state(&mut self, value: &[u8]);
    fn get_login_lat_service(&self) -> Option<&[u8]>;
    fn set_login_lat_service(&mut self, value: &[u8]);
    fn get_login_lat_node(&self) -> Option<&[u8]>;
    fn set_login_lat_node(&mut self, value: &[u8]);
    fn get_login_lat_group(&self) -> Option<&[u8]>;
    fn set_login_lat_group(&mut self, value: &[u8]);
    fn get_framed_apple_talk_link(&self) -> Option<u32>;
    fn set_framed_apple_talk_link(&mut self, value: u32);
    fn get_framed_apple_talk_network(&self) -> Option<u32>;
    fn set_framed_apple_talk_network(&mut self, value: u32);
    fn get_framed_apple_talk_zone(&self) -> Option<&[u8]>;
    fn set_framed_apple_talk_zone(&mut self, value: &[u8]);
    fn get_chap_challenge(&self) -> Option<&[u8]>;
    fn set_chap_challenge(&mut self, value: &[u8]);
    fn get_nas_port_type(&self) -> Option<u32>;
    fn set_nas_port_type(&mut self, value: u32);
    fn get_port_limit(&self) -> Option<u32>;
    fn set_port_limit(&mut self, value: u32);
    fn get_login_lat_port(&self) -> Option<&[u8]>;
    fn set_login_lat_port(&mut self, value: &[u8]);
}
impl Rfc2865Ext for Packet {
    fn get_user_name(&self) -> Option<&[u8]> {
        self.get_attribute(USER_NAME_TYPE).map(|v| v.as_slice())
    }
    fn set_user_name(&mut self, value: &[u8]) {
        self.set_attribute(USER_NAME_TYPE, value.to_vec());
    }
    fn get_user_password(&self) -> Option<&[u8]> {
        self.get_attribute(USER_PASSWORD_TYPE).map(|v| v.as_slice())
    }
    fn set_user_password(&mut self, value: &[u8]) {
        self.set_attribute(USER_PASSWORD_TYPE, value.to_vec());
    }
    fn get_chap_password(&self) -> Option<&[u8]> {
        self.get_attribute(CHAP_PASSWORD_TYPE).map(|v| v.as_slice())
    }
    fn set_chap_password(&mut self, value: &[u8]) {
        self.set_attribute(CHAP_PASSWORD_TYPE, value.to_vec());
    }
    fn get_nas_ip_address(&self) -> Option<Ipv4Addr> {
        self.get_attribute(NAS_IP_ADDRESS_TYPE).and_then(|v| {
            let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
            Some(Ipv4Addr::from(bytes))
        })
    }
    fn set_nas_ip_address(&mut self, value: Ipv4Addr) {
        let value = value.octets();
        self.set_attribute(NAS_IP_ADDRESS_TYPE, value.to_vec());
    }
    fn get_nas_port(&self) -> Option<u32> {
        self.get_attribute(NAS_PORT_TYPE).and_then(|v| {
            let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
            Some(u32::from_be_bytes(bytes))
        })
    }
    fn set_nas_port(&mut self, value: u32) {
        let value = value.to_be_bytes();
        self.set_attribute(NAS_PORT_TYPE, value.to_vec());
    }
    fn get_service_type(&self) -> Option<u32> {
        self.get_attribute(SERVICE_TYPE_TYPE).and_then(|v| {
            let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
            Some(u32::from_be_bytes(bytes))
        })
    }
    fn set_service_type(&mut self, value: u32) {
        let value = value.to_be_bytes();
        self.set_attribute(SERVICE_TYPE_TYPE, value.to_vec());
    }
    fn get_framed_protocol(&self) -> Option<u32> {
        self.get_attribute(FRAMED_PROTOCOL_TYPE).and_then(|v| {
            let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
            Some(u32::from_be_bytes(bytes))
        })
    }
    fn set_framed_protocol(&mut self, value: u32) {
        let value = value.to_be_bytes();
        self.set_attribute(FRAMED_PROTOCOL_TYPE, value.to_vec());
    }
    fn get_framed_ip_address(&self) -> Option<Ipv4Addr> {
        self.get_attribute(FRAMED_IP_ADDRESS_TYPE).and_then(|v| {
            let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
            Some(Ipv4Addr::from(bytes))
        })
    }
    fn set_framed_ip_address(&mut self, value: Ipv4Addr) {
        let value = value.octets();
        self.set_attribute(FRAMED_IP_ADDRESS_TYPE, value.to_vec());
    }
    fn get_framed_ip_netmask(&self) -> Option<Ipv4Addr> {
        self.get_attribute(FRAMED_IP_NETMASK_TYPE).and_then(|v| {
            let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
            Some(Ipv4Addr::from(bytes))
        })
    }
    fn set_framed_ip_netmask(&mut self, value: Ipv4Addr) {
        let value = value.octets();
        self.set_attribute(FRAMED_IP_NETMASK_TYPE, value.to_vec());
    }
    fn get_framed_routing(&self) -> Option<u32> {
        self.get_attribute(FRAMED_ROUTING_TYPE).and_then(|v| {
            let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
            Some(u32::from_be_bytes(bytes))
        })
    }
    fn set_framed_routing(&mut self, value: u32) {
        let value = value.to_be_bytes();
        self.set_attribute(FRAMED_ROUTING_TYPE, value.to_vec());
    }
    fn get_filter_id(&self) -> Option<&[u8]> {
        self.get_attribute(FILTER_ID_TYPE).map(|v| v.as_slice())
    }
    fn set_filter_id(&mut self, value: &[u8]) {
        self.set_attribute(FILTER_ID_TYPE, value.to_vec());
    }
    fn get_framed_mtu(&self) -> Option<u32> {
        self.get_attribute(FRAMED_MTU_TYPE).and_then(|v| {
            let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
            Some(u32::from_be_bytes(bytes))
        })
    }
    fn set_framed_mtu(&mut self, value: u32) {
        let value = value.to_be_bytes();
        self.set_attribute(FRAMED_MTU_TYPE, value.to_vec());
    }
    fn get_framed_compression(&self) -> Option<u32> {
        self.get_attribute(FRAMED_COMPRESSION_TYPE).and_then(|v| {
            let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
            Some(u32::from_be_bytes(bytes))
        })
    }
    fn set_framed_compression(&mut self, value: u32) {
        let value = value.to_be_bytes();
        self.set_attribute(FRAMED_COMPRESSION_TYPE, value.to_vec());
    }
    fn get_login_ip_host(&self) -> Option<Ipv4Addr> {
        self.get_attribute(LOGIN_IP_HOST_TYPE).and_then(|v| {
            let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
            Some(Ipv4Addr::from(bytes))
        })
    }
    fn set_login_ip_host(&mut self, value: Ipv4Addr) {
        let value = value.octets();
        self.set_attribute(LOGIN_IP_HOST_TYPE, value.to_vec());
    }
    fn get_login_service(&self) -> Option<u32> {
        self.get_attribute(LOGIN_SERVICE_TYPE).and_then(|v| {
            let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
            Some(u32::from_be_bytes(bytes))
        })
    }
    fn set_login_service(&mut self, value: u32) {
        let value = value.to_be_bytes();
        self.set_attribute(LOGIN_SERVICE_TYPE, value.to_vec());
    }
    fn get_login_tcp_port(&self) -> Option<u32> {
        self.get_attribute(LOGIN_TCP_PORT_TYPE).and_then(|v| {
            let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
            Some(u32::from_be_bytes(bytes))
        })
    }
    fn set_login_tcp_port(&mut self, value: u32) {
        let value = value.to_be_bytes();
        self.set_attribute(LOGIN_TCP_PORT_TYPE, value.to_vec());
    }
    fn get_reply_message(&self) -> Option<&[u8]> {
        self.get_attribute(REPLY_MESSAGE_TYPE).map(|v| v.as_slice())
    }
    fn set_reply_message(&mut self, value: &[u8]) {
        self.set_attribute(REPLY_MESSAGE_TYPE, value.to_vec());
    }
    fn get_callback_number(&self) -> Option<&[u8]> {
        self.get_attribute(CALLBACK_NUMBER_TYPE)
            .map(|v| v.as_slice())
    }
    fn set_callback_number(&mut self, value: &[u8]) {
        self.set_attribute(CALLBACK_NUMBER_TYPE, value.to_vec());
    }
    fn get_callback_id(&self) -> Option<&[u8]> {
        self.get_attribute(CALLBACK_ID_TYPE).map(|v| v.as_slice())
    }
    fn set_callback_id(&mut self, value: &[u8]) {
        self.set_attribute(CALLBACK_ID_TYPE, value.to_vec());
    }
    fn get_framed_route(&self) -> Option<&[u8]> {
        self.get_attribute(FRAMED_ROUTE_TYPE).map(|v| v.as_slice())
    }
    fn set_framed_route(&mut self, value: &[u8]) {
        self.set_attribute(FRAMED_ROUTE_TYPE, value.to_vec());
    }
    fn get_framed_ipx_network(&self) -> Option<Ipv4Addr> {
        self.get_attribute(FRAMED_IPX_NETWORK_TYPE).and_then(|v| {
            let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
            Some(Ipv4Addr::from(bytes))
        })
    }
    fn set_framed_ipx_network(&mut self, value: Ipv4Addr) {
        let value = value.octets();
        self.set_attribute(FRAMED_IPX_NETWORK_TYPE, value.to_vec());
    }
    fn get_state(&self) -> Option<&[u8]> {
        self.get_attribute(STATE_TYPE).map(|v| v.as_slice())
    }
    fn set_state(&mut self, value: &[u8]) {
        self.set_attribute(STATE_TYPE, value.to_vec());
    }
    fn get_class(&self) -> Option<&[u8]> {
        self.get_attribute(CLASS_TYPE).map(|v| v.as_slice())
    }
    fn set_class(&mut self, value: &[u8]) {
        self.set_attribute(CLASS_TYPE, value.to_vec());
    }
    fn get_session_timeout(&self) -> Option<u32> {
        self.get_attribute(SESSION_TIMEOUT_TYPE).and_then(|v| {
            let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
            Some(u32::from_be_bytes(bytes))
        })
    }
    fn set_session_timeout(&mut self, value: u32) {
        let value = value.to_be_bytes();
        self.set_attribute(SESSION_TIMEOUT_TYPE, value.to_vec());
    }
    fn get_idle_timeout(&self) -> Option<u32> {
        self.get_attribute(IDLE_TIMEOUT_TYPE).and_then(|v| {
            let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
            Some(u32::from_be_bytes(bytes))
        })
    }
    fn set_idle_timeout(&mut self, value: u32) {
        let value = value.to_be_bytes();
        self.set_attribute(IDLE_TIMEOUT_TYPE, value.to_vec());
    }
    fn get_termination_action(&self) -> Option<u32> {
        self.get_attribute(TERMINATION_ACTION_TYPE).and_then(|v| {
            let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
            Some(u32::from_be_bytes(bytes))
        })
    }
    fn set_termination_action(&mut self, value: u32) {
        let value = value.to_be_bytes();
        self.set_attribute(TERMINATION_ACTION_TYPE, value.to_vec());
    }
    fn get_called_station_id(&self) -> Option<&[u8]> {
        self.get_attribute(CALLED_STATION_ID_TYPE)
            .map(|v| v.as_slice())
    }
    fn set_called_station_id(&mut self, value: &[u8]) {
        self.set_attribute(CALLED_STATION_ID_TYPE, value.to_vec());
    }
    fn get_calling_station_id(&self) -> Option<&[u8]> {
        self.get_attribute(CALLING_STATION_ID_TYPE)
            .map(|v| v.as_slice())
    }
    fn set_calling_station_id(&mut self, value: &[u8]) {
        self.set_attribute(CALLING_STATION_ID_TYPE, value.to_vec());
    }
    fn get_nas_identifier(&self) -> Option<&[u8]> {
        self.get_attribute(NAS_IDENTIFIER_TYPE)
            .map(|v| v.as_slice())
    }
    fn set_nas_identifier(&mut self, value: &[u8]) {
        self.set_attribute(NAS_IDENTIFIER_TYPE, value.to_vec());
    }
    fn get_proxy_state(&self) -> Option<&[u8]> {
        self.get_attribute(PROXY_STATE_TYPE).map(|v| v.as_slice())
    }
    fn set_proxy_state(&mut self, value: &[u8]) {
        self.set_attribute(PROXY_STATE_TYPE, value.to_vec());
    }
    fn get_login_lat_service(&self) -> Option<&[u8]> {
        self.get_attribute(LOGIN_LAT_SERVICE_TYPE)
            .map(|v| v.as_slice())
    }
    fn set_login_lat_service(&mut self, value: &[u8]) {
        self.set_attribute(LOGIN_LAT_SERVICE_TYPE, value.to_vec());
    }
    fn get_login_lat_node(&self) -> Option<&[u8]> {
        self.get_attribute(LOGIN_LAT_NODE_TYPE)
            .map(|v| v.as_slice())
    }
    fn set_login_lat_node(&mut self, value: &[u8]) {
        self.set_attribute(LOGIN_LAT_NODE_TYPE, value.to_vec());
    }
    fn get_login_lat_group(&self) -> Option<&[u8]> {
        self.get_attribute(LOGIN_LAT_GROUP_TYPE)
            .map(|v| v.as_slice())
    }
    fn set_login_lat_group(&mut self, value: &[u8]) {
        self.set_attribute(LOGIN_LAT_GROUP_TYPE, value.to_vec());
    }
    fn get_framed_apple_talk_link(&self) -> Option<u32> {
        self.get_attribute(FRAMED_APPLE_TALK_LINK_TYPE)
            .and_then(|v| {
                let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
                Some(u32::from_be_bytes(bytes))
            })
    }
    fn set_framed_apple_talk_link(&mut self, value: u32) {
        let value = value.to_be_bytes();
        self.set_attribute(FRAMED_APPLE_TALK_LINK_TYPE, value.to_vec());
    }
    fn get_framed_apple_talk_network(&self) -> Option<u32> {
        self.get_attribute(FRAMED_APPLE_TALK_NETWORK_TYPE)
            .and_then(|v| {
                let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
                Some(u32::from_be_bytes(bytes))
            })
    }
    fn set_framed_apple_talk_network(&mut self, value: u32) {
        let value = value.to_be_bytes();
        self.set_attribute(FRAMED_APPLE_TALK_NETWORK_TYPE, value.to_vec());
    }
    fn get_framed_apple_talk_zone(&self) -> Option<&[u8]> {
        self.get_attribute(FRAMED_APPLE_TALK_ZONE_TYPE)
            .map(|v| v.as_slice())
    }
    fn set_framed_apple_talk_zone(&mut self, value: &[u8]) {
        self.set_attribute(FRAMED_APPLE_TALK_ZONE_TYPE, value.to_vec());
    }
    fn get_chap_challenge(&self) -> Option<&[u8]> {
        self.get_attribute(CHAP_CHALLENGE_TYPE)
            .map(|v| v.as_slice())
    }
    fn set_chap_challenge(&mut self, value: &[u8]) {
        self.set_attribute(CHAP_CHALLENGE_TYPE, value.to_vec());
    }
    fn get_nas_port_type(&self) -> Option<u32> {
        self.get_attribute(NAS_PORT_TYPE_TYPE).and_then(|v| {
            let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
            Some(u32::from_be_bytes(bytes))
        })
    }
    fn set_nas_port_type(&mut self, value: u32) {
        let value = value.to_be_bytes();
        self.set_attribute(NAS_PORT_TYPE_TYPE, value.to_vec());
    }
    fn get_port_limit(&self) -> Option<u32> {
        self.get_attribute(PORT_LIMIT_TYPE).and_then(|v| {
            let bytes: [u8; 4] = v.as_slice().try_into().ok()?;
            Some(u32::from_be_bytes(bytes))
        })
    }
    fn set_port_limit(&mut self, value: u32) {
        let value = value.to_be_bytes();
        self.set_attribute(PORT_LIMIT_TYPE, value.to_vec());
    }
    fn get_login_lat_port(&self) -> Option<&[u8]> {
        self.get_attribute(LOGIN_LAT_PORT_TYPE)
            .map(|v| v.as_slice())
    }
    fn set_login_lat_port(&mut self, value: &[u8]) {
        self.set_attribute(LOGIN_LAT_PORT_TYPE, value.to_vec());
    }
}
