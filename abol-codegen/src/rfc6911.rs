use abol_core::{attribute::FromRadiusAttribute, attribute::ToRadiusAttribute, packet::Packet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;
pub const FRAMED_IPV6_ADDRESS_TYPE: u8 = 168u8;
pub const DNS_SERVER_IPV6_ADDRESS_TYPE: u8 = 169u8;
pub const ROUTE_IPV6_INFORMATION_TYPE: u8 = 170u8;
pub const DELEGATED_IPV6_PREFIX_POOL_TYPE: u8 = 171u8;
pub const STATEFUL_IPV6_ADDRESS_POOL_TYPE: u8 = 172u8;
pub trait Rfc6911Ext {
    fn get_framed_ipv6_address(&self) -> Option<Ipv6Addr>;
    fn set_framed_ipv6_address(&mut self, value: Ipv6Addr);
    fn get_dns_server_ipv6_address(&self) -> Option<Ipv6Addr>;
    fn set_dns_server_ipv6_address(&mut self, value: Ipv6Addr);
    fn get_route_ipv6_information(&self) -> Option<Vec<u8>>;
    fn set_route_ipv6_information(&mut self, value: Vec<u8>);
    fn get_delegated_ipv6_prefix_pool(&self) -> Option<String>;
    fn set_delegated_ipv6_prefix_pool(&mut self, value: impl Into<String>);
    fn get_stateful_ipv6_address_pool(&self) -> Option<String>;
    fn set_stateful_ipv6_address_pool(&mut self, value: impl Into<String>);
}
impl Rfc6911Ext for Packet {
    fn get_framed_ipv6_address(&self) -> Option<Ipv6Addr> {
        self.get_attribute_as::<Ipv6Addr>(FRAMED_IPV6_ADDRESS_TYPE)
    }
    fn set_framed_ipv6_address(&mut self, value: Ipv6Addr) {
        let wire_val: Ipv6Addr = value.into();
        self.set_attribute_as::<Ipv6Addr>(FRAMED_IPV6_ADDRESS_TYPE, wire_val);
    }
    fn get_dns_server_ipv6_address(&self) -> Option<Ipv6Addr> {
        self.get_attribute_as::<Ipv6Addr>(DNS_SERVER_IPV6_ADDRESS_TYPE)
    }
    fn set_dns_server_ipv6_address(&mut self, value: Ipv6Addr) {
        let wire_val: Ipv6Addr = value.into();
        self.set_attribute_as::<Ipv6Addr>(DNS_SERVER_IPV6_ADDRESS_TYPE, wire_val);
    }
    fn get_route_ipv6_information(&self) -> Option<Vec<u8>> {
        self.get_attribute_as::<Vec<u8>>(ROUTE_IPV6_INFORMATION_TYPE)
    }
    fn set_route_ipv6_information(&mut self, value: Vec<u8>) {
        let wire_val: Vec<u8> = value.into();
        self.set_attribute_as::<Vec<u8>>(ROUTE_IPV6_INFORMATION_TYPE, wire_val);
    }
    fn get_delegated_ipv6_prefix_pool(&self) -> Option<String> {
        self.get_attribute_as::<String>(DELEGATED_IPV6_PREFIX_POOL_TYPE)
    }
    fn set_delegated_ipv6_prefix_pool(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(DELEGATED_IPV6_PREFIX_POOL_TYPE, wire_val);
    }
    fn get_stateful_ipv6_address_pool(&self) -> Option<String> {
        self.get_attribute_as::<String>(STATEFUL_IPV6_ADDRESS_POOL_TYPE)
    }
    fn set_stateful_ipv6_address_pool(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(STATEFUL_IPV6_ADDRESS_POOL_TYPE, wire_val);
    }
}
