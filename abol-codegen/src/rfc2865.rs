use abol_core::packet::Packet;
use std::net::Ipv4Addr;

pub const USER_NAME_TYPE: u8 = 1u8;
pub const USER_PASSWORD_TYPE: u8 = 2u8;
pub const CHAP_PASSWORD_TYPE: u8 = 3u8;
pub const NAS_IP_ADDRESS_TYPE: u8 = 4u8;
pub const NAS_PORT_TYPE: u8 = 5u8;
pub const SERVICE_TYPE_TYPE: u8 = 6u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ServiceType {
    LoginUser,
    FramedUser,
    CallbackLoginUser,
    CallbackFramedUser,
    OutboundUser,
    AdministrativeUser,
    NasPromptUser,
    AuthenticateOnly,
    CallbackNasPrompt,
    CallCheck,
    CallbackAdministrative,
    Unknown(u32),
}
impl From<u32> for ServiceType {
    fn from(v: u32) -> Self {
        match v {
            1u32 => Self::LoginUser,
            2u32 => Self::FramedUser,
            3u32 => Self::CallbackLoginUser,
            4u32 => Self::CallbackFramedUser,
            5u32 => Self::OutboundUser,
            6u32 => Self::AdministrativeUser,
            7u32 => Self::NasPromptUser,
            8u32 => Self::AuthenticateOnly,
            9u32 => Self::CallbackNasPrompt,
            10u32 => Self::CallCheck,
            11u32 => Self::CallbackAdministrative,
            other => Self::Unknown(other),
        }
    }
}
impl From<ServiceType> for u32 {
    fn from(e: ServiceType) -> Self {
        match e {
            ServiceType::LoginUser => 1u32,
            ServiceType::FramedUser => 2u32,
            ServiceType::CallbackLoginUser => 3u32,
            ServiceType::CallbackFramedUser => 4u32,
            ServiceType::OutboundUser => 5u32,
            ServiceType::AdministrativeUser => 6u32,
            ServiceType::NasPromptUser => 7u32,
            ServiceType::AuthenticateOnly => 8u32,
            ServiceType::CallbackNasPrompt => 9u32,
            ServiceType::CallCheck => 10u32,
            ServiceType::CallbackAdministrative => 11u32,
            ServiceType::Unknown(v) => v,
        }
    }
}
pub const FRAMED_PROTOCOL_TYPE: u8 = 7u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FramedProtocol {
    Ppp,
    Slip,
    Arap,
    GandalfSlml,
    XylogicsIpxSlip,
    X75Synchronous,
    Unknown(u32),
}
impl From<u32> for FramedProtocol {
    fn from(v: u32) -> Self {
        match v {
            1u32 => Self::Ppp,
            2u32 => Self::Slip,
            3u32 => Self::Arap,
            4u32 => Self::GandalfSlml,
            5u32 => Self::XylogicsIpxSlip,
            6u32 => Self::X75Synchronous,
            other => Self::Unknown(other),
        }
    }
}
impl From<FramedProtocol> for u32 {
    fn from(e: FramedProtocol) -> Self {
        match e {
            FramedProtocol::Ppp => 1u32,
            FramedProtocol::Slip => 2u32,
            FramedProtocol::Arap => 3u32,
            FramedProtocol::GandalfSlml => 4u32,
            FramedProtocol::XylogicsIpxSlip => 5u32,
            FramedProtocol::X75Synchronous => 6u32,
            FramedProtocol::Unknown(v) => v,
        }
    }
}
pub const FRAMED_IP_ADDRESS_TYPE: u8 = 8u8;
pub const FRAMED_IP_NETMASK_TYPE: u8 = 9u8;
pub const FRAMED_ROUTING_TYPE: u8 = 10u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FramedRouting {
    None,
    Broadcast,
    Listen,
    BroadcastListen,
    Unknown(u32),
}
impl From<u32> for FramedRouting {
    fn from(v: u32) -> Self {
        match v {
            0u32 => Self::None,
            1u32 => Self::Broadcast,
            2u32 => Self::Listen,
            3u32 => Self::BroadcastListen,
            other => Self::Unknown(other),
        }
    }
}
impl From<FramedRouting> for u32 {
    fn from(e: FramedRouting) -> Self {
        match e {
            FramedRouting::None => 0u32,
            FramedRouting::Broadcast => 1u32,
            FramedRouting::Listen => 2u32,
            FramedRouting::BroadcastListen => 3u32,
            FramedRouting::Unknown(v) => v,
        }
    }
}
pub const FILTER_ID_TYPE: u8 = 11u8;
pub const FRAMED_MTU_TYPE: u8 = 12u8;
pub const FRAMED_COMPRESSION_TYPE: u8 = 13u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FramedCompression {
    None,
    VanJacobsonTcpIp,
    IpxHeaderCompression,
    StacLzs,
    Unknown(u32),
}
impl From<u32> for FramedCompression {
    fn from(v: u32) -> Self {
        match v {
            0u32 => Self::None,
            1u32 => Self::VanJacobsonTcpIp,
            2u32 => Self::IpxHeaderCompression,
            3u32 => Self::StacLzs,
            other => Self::Unknown(other),
        }
    }
}
impl From<FramedCompression> for u32 {
    fn from(e: FramedCompression) -> Self {
        match e {
            FramedCompression::None => 0u32,
            FramedCompression::VanJacobsonTcpIp => 1u32,
            FramedCompression::IpxHeaderCompression => 2u32,
            FramedCompression::StacLzs => 3u32,
            FramedCompression::Unknown(v) => v,
        }
    }
}
pub const LOGIN_IP_HOST_TYPE: u8 = 14u8;
pub const LOGIN_SERVICE_TYPE: u8 = 15u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LoginService {
    Telnet,
    Rlogin,
    TcpClear,
    PortMaster,
    Lat,
    X25Pad,
    X25T3pos,
    TcpClearQuiet,
    Unknown(u32),
}
impl From<u32> for LoginService {
    fn from(v: u32) -> Self {
        match v {
            0u32 => Self::Telnet,
            1u32 => Self::Rlogin,
            2u32 => Self::TcpClear,
            3u32 => Self::PortMaster,
            4u32 => Self::Lat,
            5u32 => Self::X25Pad,
            6u32 => Self::X25T3pos,
            8u32 => Self::TcpClearQuiet,
            other => Self::Unknown(other),
        }
    }
}
impl From<LoginService> for u32 {
    fn from(e: LoginService) -> Self {
        match e {
            LoginService::Telnet => 0u32,
            LoginService::Rlogin => 1u32,
            LoginService::TcpClear => 2u32,
            LoginService::PortMaster => 3u32,
            LoginService::Lat => 4u32,
            LoginService::X25Pad => 5u32,
            LoginService::X25T3pos => 6u32,
            LoginService::TcpClearQuiet => 8u32,
            LoginService::Unknown(v) => v,
        }
    }
}
pub const LOGIN_TCP_PORT_TYPE: u8 = 16u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LoginTcpPort {
    Telnet,
    Rlogin,
    Rsh,
    Unknown(u32),
}
impl From<u32> for LoginTcpPort {
    fn from(v: u32) -> Self {
        match v {
            23u32 => Self::Telnet,
            513u32 => Self::Rlogin,
            514u32 => Self::Rsh,
            other => Self::Unknown(other),
        }
    }
}
impl From<LoginTcpPort> for u32 {
    fn from(e: LoginTcpPort) -> Self {
        match e {
            LoginTcpPort::Telnet => 23u32,
            LoginTcpPort::Rlogin => 513u32,
            LoginTcpPort::Rsh => 514u32,
            LoginTcpPort::Unknown(v) => v,
        }
    }
}
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TerminationAction {
    Default,
    RadiusRequest,
    Unknown(u32),
}
impl From<u32> for TerminationAction {
    fn from(v: u32) -> Self {
        match v {
            0u32 => Self::Default,
            1u32 => Self::RadiusRequest,
            other => Self::Unknown(other),
        }
    }
}
impl From<TerminationAction> for u32 {
    fn from(e: TerminationAction) -> Self {
        match e {
            TerminationAction::Default => 0u32,
            TerminationAction::RadiusRequest => 1u32,
            TerminationAction::Unknown(v) => v,
        }
    }
}
pub const CALLED_STATION_ID_TYPE: u8 = 30u8;
pub const CALLING_STATION_ID_TYPE: u8 = 31u8;
pub const NAS_IDENTIFIER_TYPE: u8 = 32u8;
pub const PROXY_STATE_TYPE: u8 = 33u8;
pub const LOGIN_LAT_SERVICE_TYPE: u8 = 34u8;
pub const LOGIN_LAT_NODE_TYPE: u8 = 35u8;
pub const LOGIN_LAT_GROUP_TYPE: u8 = 36u8;
pub const FRAMED_APPLETALK_LINK_TYPE: u8 = 37u8;
pub const FRAMED_APPLETALK_NETWORK_TYPE: u8 = 38u8;
pub const FRAMED_APPLETALK_ZONE_TYPE: u8 = 39u8;
pub const CHAP_CHALLENGE_TYPE: u8 = 60u8;
pub const NAS_PORT_TYPE_TYPE: u8 = 61u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NasPortType {
    Async,
    Sync,
    Isdn,
    IsdnV120,
    IsdnV110,
    Virtual,
    Piafs,
    HdlcClearChannel,
    X25,
    X75,
    G3Fax,
    Sdsl,
    AdslCap,
    AdslDmt,
    Idsl,
    Ethernet,
    XDsl,
    Cable,
    WirelessOther,
    Wireless80211,
    Unknown(u32),
}
impl From<u32> for NasPortType {
    fn from(v: u32) -> Self {
        match v {
            0u32 => Self::Async,
            1u32 => Self::Sync,
            2u32 => Self::Isdn,
            3u32 => Self::IsdnV120,
            4u32 => Self::IsdnV110,
            5u32 => Self::Virtual,
            6u32 => Self::Piafs,
            7u32 => Self::HdlcClearChannel,
            8u32 => Self::X25,
            9u32 => Self::X75,
            10u32 => Self::G3Fax,
            11u32 => Self::Sdsl,
            12u32 => Self::AdslCap,
            13u32 => Self::AdslDmt,
            14u32 => Self::Idsl,
            15u32 => Self::Ethernet,
            16u32 => Self::XDsl,
            17u32 => Self::Cable,
            18u32 => Self::WirelessOther,
            19u32 => Self::Wireless80211,
            other => Self::Unknown(other),
        }
    }
}
impl From<NasPortType> for u32 {
    fn from(e: NasPortType) -> Self {
        match e {
            NasPortType::Async => 0u32,
            NasPortType::Sync => 1u32,
            NasPortType::Isdn => 2u32,
            NasPortType::IsdnV120 => 3u32,
            NasPortType::IsdnV110 => 4u32,
            NasPortType::Virtual => 5u32,
            NasPortType::Piafs => 6u32,
            NasPortType::HdlcClearChannel => 7u32,
            NasPortType::X25 => 8u32,
            NasPortType::X75 => 9u32,
            NasPortType::G3Fax => 10u32,
            NasPortType::Sdsl => 11u32,
            NasPortType::AdslCap => 12u32,
            NasPortType::AdslDmt => 13u32,
            NasPortType::Idsl => 14u32,
            NasPortType::Ethernet => 15u32,
            NasPortType::XDsl => 16u32,
            NasPortType::Cable => 17u32,
            NasPortType::WirelessOther => 18u32,
            NasPortType::Wireless80211 => 19u32,
            NasPortType::Unknown(v) => v,
        }
    }
}
pub const PORT_LIMIT_TYPE: u8 = 62u8;
pub const LOGIN_LAT_PORT_TYPE: u8 = 63u8;
pub trait Rfc2865Ext {
    fn get_user_name(&self) -> Option<String>;
    fn set_user_name(&mut self, value: impl Into<String>);
    fn get_user_password(&self) -> Option<String>;
    fn set_user_password(&mut self, value: impl Into<String>);
    fn get_chap_password(&self) -> Option<Vec<u8>>;
    fn set_chap_password(&mut self, value: impl Into<Vec<u8>>);
    fn get_nas_ip_address(&self) -> Option<Ipv4Addr>;
    fn set_nas_ip_address(&mut self, value: Ipv4Addr);
    fn get_nas_port(&self) -> Option<u32>;
    fn set_nas_port(&mut self, value: u32);
    fn get_service_type(&self) -> Option<ServiceType>;
    fn set_service_type(&mut self, value: ServiceType);
    fn get_framed_protocol(&self) -> Option<FramedProtocol>;
    fn set_framed_protocol(&mut self, value: FramedProtocol);
    fn get_framed_ip_address(&self) -> Option<Ipv4Addr>;
    fn set_framed_ip_address(&mut self, value: Ipv4Addr);
    fn get_framed_ip_netmask(&self) -> Option<Ipv4Addr>;
    fn set_framed_ip_netmask(&mut self, value: Ipv4Addr);
    fn get_framed_routing(&self) -> Option<FramedRouting>;
    fn set_framed_routing(&mut self, value: FramedRouting);
    fn get_filter_id(&self) -> Option<String>;
    fn set_filter_id(&mut self, value: impl Into<String>);
    fn get_framed_mtu(&self) -> Option<u32>;
    fn set_framed_mtu(&mut self, value: u32);
    fn get_framed_compression(&self) -> Option<FramedCompression>;
    fn set_framed_compression(&mut self, value: FramedCompression);
    fn get_login_ip_host(&self) -> Option<Ipv4Addr>;
    fn set_login_ip_host(&mut self, value: Ipv4Addr);
    fn get_login_service(&self) -> Option<LoginService>;
    fn set_login_service(&mut self, value: LoginService);
    fn get_login_tcp_port(&self) -> Option<LoginTcpPort>;
    fn set_login_tcp_port(&mut self, value: LoginTcpPort);
    fn get_reply_message(&self) -> Option<String>;
    fn set_reply_message(&mut self, value: impl Into<String>);
    fn get_callback_number(&self) -> Option<String>;
    fn set_callback_number(&mut self, value: impl Into<String>);
    fn get_callback_id(&self) -> Option<String>;
    fn set_callback_id(&mut self, value: impl Into<String>);
    fn get_framed_route(&self) -> Option<String>;
    fn set_framed_route(&mut self, value: impl Into<String>);
    fn get_framed_ipx_network(&self) -> Option<Ipv4Addr>;
    fn set_framed_ipx_network(&mut self, value: Ipv4Addr);
    fn get_state(&self) -> Option<Vec<u8>>;
    fn set_state(&mut self, value: impl Into<Vec<u8>>);
    fn get_class(&self) -> Option<Vec<u8>>;
    fn set_class(&mut self, value: impl Into<Vec<u8>>);
    fn get_vendor_specific(&self) -> Option<Vec<u8>>;
    fn set_vendor_specific(&mut self, value: impl Into<Vec<u8>>);
    fn get_session_timeout(&self) -> Option<u32>;
    fn set_session_timeout(&mut self, value: u32);
    fn get_idle_timeout(&self) -> Option<u32>;
    fn set_idle_timeout(&mut self, value: u32);
    fn get_termination_action(&self) -> Option<TerminationAction>;
    fn set_termination_action(&mut self, value: TerminationAction);
    fn get_called_station_id(&self) -> Option<String>;
    fn set_called_station_id(&mut self, value: impl Into<String>);
    fn get_calling_station_id(&self) -> Option<String>;
    fn set_calling_station_id(&mut self, value: impl Into<String>);
    fn get_nas_identifier(&self) -> Option<String>;
    fn set_nas_identifier(&mut self, value: impl Into<String>);
    fn get_proxy_state(&self) -> Option<Vec<u8>>;
    fn set_proxy_state(&mut self, value: impl Into<Vec<u8>>);
    fn get_login_lat_service(&self) -> Option<String>;
    fn set_login_lat_service(&mut self, value: impl Into<String>);
    fn get_login_lat_node(&self) -> Option<String>;
    fn set_login_lat_node(&mut self, value: impl Into<String>);
    fn get_login_lat_group(&self) -> Option<Vec<u8>>;
    fn set_login_lat_group(&mut self, value: impl Into<Vec<u8>>);
    fn get_framed_appletalk_link(&self) -> Option<u32>;
    fn set_framed_appletalk_link(&mut self, value: u32);
    fn get_framed_appletalk_network(&self) -> Option<u32>;
    fn set_framed_appletalk_network(&mut self, value: u32);
    fn get_framed_appletalk_zone(&self) -> Option<String>;
    fn set_framed_appletalk_zone(&mut self, value: impl Into<String>);
    fn get_chap_challenge(&self) -> Option<Vec<u8>>;
    fn set_chap_challenge(&mut self, value: impl Into<Vec<u8>>);
    fn get_nas_port_type(&self) -> Option<NasPortType>;
    fn set_nas_port_type(&mut self, value: NasPortType);
    fn get_port_limit(&self) -> Option<u32>;
    fn set_port_limit(&mut self, value: u32);
    fn get_login_lat_port(&self) -> Option<String>;
    fn set_login_lat_port(&mut self, value: impl Into<String>);
}
impl Rfc2865Ext for Packet {
    fn get_user_name(&self) -> Option<String> {
        self.get_attribute_as::<String>(USER_NAME_TYPE)
    }
    fn set_user_name(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(USER_NAME_TYPE, wire_val);
    }
    fn get_user_password(&self) -> Option<String> {
        self.get_attribute_as::<String>(USER_PASSWORD_TYPE)
    }
    fn set_user_password(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(USER_PASSWORD_TYPE, wire_val);
    }
    fn get_chap_password(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(CHAP_PASSWORD_TYPE)
    }
    fn set_chap_password(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(CHAP_PASSWORD_TYPE, wire_val);
    }
    fn get_nas_ip_address(&self) -> Option<Ipv4Addr> {
        self.get_attribute_as::<Ipv4Addr>(NAS_IP_ADDRESS_TYPE)
    }
    fn set_nas_ip_address(&mut self, value: Ipv4Addr) {
        let wire_val = value;
        self.set_attribute_as::<Ipv4Addr>(NAS_IP_ADDRESS_TYPE, wire_val);
    }
    fn get_nas_port(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(NAS_PORT_TYPE)
    }
    fn set_nas_port(&mut self, value: u32) {
        let wire_val = value;
        self.set_attribute_as::<u32>(NAS_PORT_TYPE, wire_val);
    }
    fn get_service_type(&self) -> Option<ServiceType> {
        self.get_attribute_as::<u32>(SERVICE_TYPE_TYPE)
            .map(ServiceType::from)
    }
    fn set_service_type(&mut self, value: ServiceType) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(SERVICE_TYPE_TYPE, wire_val);
    }
    fn get_framed_protocol(&self) -> Option<FramedProtocol> {
        self.get_attribute_as::<u32>(FRAMED_PROTOCOL_TYPE)
            .map(FramedProtocol::from)
    }
    fn set_framed_protocol(&mut self, value: FramedProtocol) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(FRAMED_PROTOCOL_TYPE, wire_val);
    }
    fn get_framed_ip_address(&self) -> Option<Ipv4Addr> {
        self.get_attribute_as::<Ipv4Addr>(FRAMED_IP_ADDRESS_TYPE)
    }
    fn set_framed_ip_address(&mut self, value: Ipv4Addr) {
        let wire_val = value;
        self.set_attribute_as::<Ipv4Addr>(FRAMED_IP_ADDRESS_TYPE, wire_val);
    }
    fn get_framed_ip_netmask(&self) -> Option<Ipv4Addr> {
        self.get_attribute_as::<Ipv4Addr>(FRAMED_IP_NETMASK_TYPE)
    }
    fn set_framed_ip_netmask(&mut self, value: Ipv4Addr) {
        let wire_val = value;
        self.set_attribute_as::<Ipv4Addr>(FRAMED_IP_NETMASK_TYPE, wire_val);
    }
    fn get_framed_routing(&self) -> Option<FramedRouting> {
        self.get_attribute_as::<u32>(FRAMED_ROUTING_TYPE)
            .map(FramedRouting::from)
    }
    fn set_framed_routing(&mut self, value: FramedRouting) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(FRAMED_ROUTING_TYPE, wire_val);
    }
    fn get_filter_id(&self) -> Option<String> {
        self.get_attribute_as::<String>(FILTER_ID_TYPE)
    }
    fn set_filter_id(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(FILTER_ID_TYPE, wire_val);
    }
    fn get_framed_mtu(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(FRAMED_MTU_TYPE)
    }
    fn set_framed_mtu(&mut self, value: u32) {
        let wire_val = value;
        self.set_attribute_as::<u32>(FRAMED_MTU_TYPE, wire_val);
    }
    fn get_framed_compression(&self) -> Option<FramedCompression> {
        self.get_attribute_as::<u32>(FRAMED_COMPRESSION_TYPE)
            .map(FramedCompression::from)
    }
    fn set_framed_compression(&mut self, value: FramedCompression) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(FRAMED_COMPRESSION_TYPE, wire_val);
    }
    fn get_login_ip_host(&self) -> Option<Ipv4Addr> {
        self.get_attribute_as::<Ipv4Addr>(LOGIN_IP_HOST_TYPE)
    }
    fn set_login_ip_host(&mut self, value: Ipv4Addr) {
        let wire_val = value;
        self.set_attribute_as::<Ipv4Addr>(LOGIN_IP_HOST_TYPE, wire_val);
    }
    fn get_login_service(&self) -> Option<LoginService> {
        self.get_attribute_as::<u32>(LOGIN_SERVICE_TYPE)
            .map(LoginService::from)
    }
    fn set_login_service(&mut self, value: LoginService) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(LOGIN_SERVICE_TYPE, wire_val);
    }
    fn get_login_tcp_port(&self) -> Option<LoginTcpPort> {
        self.get_attribute_as::<u32>(LOGIN_TCP_PORT_TYPE)
            .map(LoginTcpPort::from)
    }
    fn set_login_tcp_port(&mut self, value: LoginTcpPort) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(LOGIN_TCP_PORT_TYPE, wire_val);
    }
    fn get_reply_message(&self) -> Option<String> {
        self.get_attribute_as::<String>(REPLY_MESSAGE_TYPE)
    }
    fn set_reply_message(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(REPLY_MESSAGE_TYPE, wire_val);
    }
    fn get_callback_number(&self) -> Option<String> {
        self.get_attribute_as::<String>(CALLBACK_NUMBER_TYPE)
    }
    fn set_callback_number(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(CALLBACK_NUMBER_TYPE, wire_val);
    }
    fn get_callback_id(&self) -> Option<String> {
        self.get_attribute_as::<String>(CALLBACK_ID_TYPE)
    }
    fn set_callback_id(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(CALLBACK_ID_TYPE, wire_val);
    }
    fn get_framed_route(&self) -> Option<String> {
        self.get_attribute_as::<String>(FRAMED_ROUTE_TYPE)
    }
    fn set_framed_route(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(FRAMED_ROUTE_TYPE, wire_val);
    }
    fn get_framed_ipx_network(&self) -> Option<Ipv4Addr> {
        self.get_attribute_as::<Ipv4Addr>(FRAMED_IPX_NETWORK_TYPE)
    }
    fn set_framed_ipx_network(&mut self, value: Ipv4Addr) {
        let wire_val = value;
        self.set_attribute_as::<Ipv4Addr>(FRAMED_IPX_NETWORK_TYPE, wire_val);
    }
    fn get_state(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(STATE_TYPE)
    }
    fn set_state(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(STATE_TYPE, wire_val);
    }
    fn get_class(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(CLASS_TYPE)
    }
    fn set_class(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(CLASS_TYPE, wire_val);
    }
    fn get_vendor_specific(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(VENDOR_SPECIFIC_TYPE)
    }
    fn set_vendor_specific(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(VENDOR_SPECIFIC_TYPE, wire_val);
    }
    fn get_session_timeout(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(SESSION_TIMEOUT_TYPE)
    }
    fn set_session_timeout(&mut self, value: u32) {
        let wire_val = value;
        self.set_attribute_as::<u32>(SESSION_TIMEOUT_TYPE, wire_val);
    }
    fn get_idle_timeout(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(IDLE_TIMEOUT_TYPE)
    }
    fn set_idle_timeout(&mut self, value: u32) {
        let wire_val = value;
        self.set_attribute_as::<u32>(IDLE_TIMEOUT_TYPE, wire_val);
    }
    fn get_termination_action(&self) -> Option<TerminationAction> {
        self.get_attribute_as::<u32>(TERMINATION_ACTION_TYPE)
            .map(TerminationAction::from)
    }
    fn set_termination_action(&mut self, value: TerminationAction) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(TERMINATION_ACTION_TYPE, wire_val);
    }
    fn get_called_station_id(&self) -> Option<String> {
        self.get_attribute_as::<String>(CALLED_STATION_ID_TYPE)
    }
    fn set_called_station_id(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(CALLED_STATION_ID_TYPE, wire_val);
    }
    fn get_calling_station_id(&self) -> Option<String> {
        self.get_attribute_as::<String>(CALLING_STATION_ID_TYPE)
    }
    fn set_calling_station_id(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(CALLING_STATION_ID_TYPE, wire_val);
    }
    fn get_nas_identifier(&self) -> Option<String> {
        self.get_attribute_as::<String>(NAS_IDENTIFIER_TYPE)
    }
    fn set_nas_identifier(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(NAS_IDENTIFIER_TYPE, wire_val);
    }
    fn get_proxy_state(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(PROXY_STATE_TYPE)
    }
    fn set_proxy_state(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(PROXY_STATE_TYPE, wire_val);
    }
    fn get_login_lat_service(&self) -> Option<String> {
        self.get_attribute_as::<String>(LOGIN_LAT_SERVICE_TYPE)
    }
    fn set_login_lat_service(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(LOGIN_LAT_SERVICE_TYPE, wire_val);
    }
    fn get_login_lat_node(&self) -> Option<String> {
        self.get_attribute_as::<String>(LOGIN_LAT_NODE_TYPE)
    }
    fn set_login_lat_node(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(LOGIN_LAT_NODE_TYPE, wire_val);
    }
    fn get_login_lat_group(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(LOGIN_LAT_GROUP_TYPE)
    }
    fn set_login_lat_group(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(LOGIN_LAT_GROUP_TYPE, wire_val);
    }
    fn get_framed_appletalk_link(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(FRAMED_APPLETALK_LINK_TYPE)
    }
    fn set_framed_appletalk_link(&mut self, value: u32) {
        let wire_val = value;
        self.set_attribute_as::<u32>(FRAMED_APPLETALK_LINK_TYPE, wire_val);
    }
    fn get_framed_appletalk_network(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(FRAMED_APPLETALK_NETWORK_TYPE)
    }
    fn set_framed_appletalk_network(&mut self, value: u32) {
        let wire_val = value;
        self.set_attribute_as::<u32>(FRAMED_APPLETALK_NETWORK_TYPE, wire_val);
    }
    fn get_framed_appletalk_zone(&self) -> Option<String> {
        self.get_attribute_as::<String>(FRAMED_APPLETALK_ZONE_TYPE)
    }
    fn set_framed_appletalk_zone(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(FRAMED_APPLETALK_ZONE_TYPE, wire_val);
    }
    fn get_chap_challenge(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(CHAP_CHALLENGE_TYPE)
    }
    fn set_chap_challenge(&mut self, value: impl Into<Vec<u8>>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(CHAP_CHALLENGE_TYPE, wire_val);
    }
    fn get_nas_port_type(&self) -> Option<NasPortType> {
        self.get_attribute_as::<u32>(NAS_PORT_TYPE_TYPE)
            .map(NasPortType::from)
    }
    fn set_nas_port_type(&mut self, value: NasPortType) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(NAS_PORT_TYPE_TYPE, wire_val);
    }
    fn get_port_limit(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(PORT_LIMIT_TYPE)
    }
    fn set_port_limit(&mut self, value: u32) {
        let wire_val = value;
        self.set_attribute_as::<u32>(PORT_LIMIT_TYPE, wire_val);
    }
    fn get_login_lat_port(&self) -> Option<String> {
        self.get_attribute_as::<String>(LOGIN_LAT_PORT_TYPE)
    }
    fn set_login_lat_port(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(LOGIN_LAT_PORT_TYPE, wire_val);
    }
}
