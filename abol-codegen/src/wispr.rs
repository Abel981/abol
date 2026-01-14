use abol_core::packet::Packet;
pub const VENDOR_WIS_PR: u32 = 14122u32;
pub const WISPR_LOCATION_ID_TYPE: u8 = 1u8;
pub const WISPR_LOCATION_NAME_TYPE: u8 = 2u8;
pub const WISPR_LOGOFF_URL_TYPE: u8 = 3u8;
pub const WISPR_REDIRECTION_URL_TYPE: u8 = 4u8;
pub const WISPR_BANDWIDTH_MIN_UP_TYPE: u8 = 5u8;
pub const WISPR_BANDWIDTH_MIN_DOWN_TYPE: u8 = 6u8;
pub const WISPR_BANDWIDTH_MAX_UP_TYPE: u8 = 7u8;
pub const WISPR_BANDWIDTH_MAX_DOWN_TYPE: u8 = 8u8;
pub const WISPR_SESSION_TERMINATE_TIME_TYPE: u8 = 9u8;
pub const WISPR_SESSION_TERMINATE_END_OF_DAY_TYPE: u8 = 10u8;
pub const WISPR_BILLING_CLASS_OF_SERVICE_TYPE: u8 = 11u8;
pub trait WisprExt {
    fn get_wispr_location_id(&self) -> Option<String>;
    fn set_wispr_location_id(&mut self, value: impl Into<String>);
    fn get_wispr_location_name(&self) -> Option<String>;
    fn set_wispr_location_name(&mut self, value: impl Into<String>);
    fn get_wispr_logoff_url(&self) -> Option<String>;
    fn set_wispr_logoff_url(&mut self, value: impl Into<String>);
    fn get_wispr_redirection_url(&self) -> Option<String>;
    fn set_wispr_redirection_url(&mut self, value: impl Into<String>);
    fn get_wispr_bandwidth_min_up(&self) -> Option<u32>;
    fn set_wispr_bandwidth_min_up(&mut self, value: u32);
    fn get_wispr_bandwidth_min_down(&self) -> Option<u32>;
    fn set_wispr_bandwidth_min_down(&mut self, value: u32);
    fn get_wispr_bandwidth_max_up(&self) -> Option<u32>;
    fn set_wispr_bandwidth_max_up(&mut self, value: u32);
    fn get_wispr_bandwidth_max_down(&self) -> Option<u32>;
    fn set_wispr_bandwidth_max_down(&mut self, value: u32);
    fn get_wispr_session_terminate_time(&self) -> Option<String>;
    fn set_wispr_session_terminate_time(&mut self, value: impl Into<String>);
    fn get_wispr_session_terminate_end_of_day(&self) -> Option<String>;
    fn set_wispr_session_terminate_end_of_day(&mut self, value: impl Into<String>);
    fn get_wispr_billing_class_of_service(&self) -> Option<String>;
    fn set_wispr_billing_class_of_service(&mut self, value: impl Into<String>);
}
impl WisprExt for Packet {
    fn get_wispr_location_id(&self) -> Option<String> {
        self.get_attribute_as::<String>(WISPR_LOCATION_ID_TYPE)
    }
    fn set_wispr_location_id(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(WISPR_LOCATION_ID_TYPE, wire_val);
    }
    fn get_wispr_location_name(&self) -> Option<String> {
        self.get_attribute_as::<String>(WISPR_LOCATION_NAME_TYPE)
    }
    fn set_wispr_location_name(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(WISPR_LOCATION_NAME_TYPE, wire_val);
    }
    fn get_wispr_logoff_url(&self) -> Option<String> {
        self.get_attribute_as::<String>(WISPR_LOGOFF_URL_TYPE)
    }
    fn set_wispr_logoff_url(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(WISPR_LOGOFF_URL_TYPE, wire_val);
    }
    fn get_wispr_redirection_url(&self) -> Option<String> {
        self.get_attribute_as::<String>(WISPR_REDIRECTION_URL_TYPE)
    }
    fn set_wispr_redirection_url(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(WISPR_REDIRECTION_URL_TYPE, wire_val);
    }
    fn get_wispr_bandwidth_min_up(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(WISPR_BANDWIDTH_MIN_UP_TYPE)
    }
    fn set_wispr_bandwidth_min_up(&mut self, value: u32) {
        let wire_val = value;
        self.set_attribute_as::<u32>(WISPR_BANDWIDTH_MIN_UP_TYPE, wire_val);
    }
    fn get_wispr_bandwidth_min_down(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(WISPR_BANDWIDTH_MIN_DOWN_TYPE)
    }
    fn set_wispr_bandwidth_min_down(&mut self, value: u32) {
        let wire_val = value;
        self.set_attribute_as::<u32>(WISPR_BANDWIDTH_MIN_DOWN_TYPE, wire_val);
    }
    fn get_wispr_bandwidth_max_up(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(WISPR_BANDWIDTH_MAX_UP_TYPE)
    }
    fn set_wispr_bandwidth_max_up(&mut self, value: u32) {
        let wire_val = value;
        self.set_attribute_as::<u32>(WISPR_BANDWIDTH_MAX_UP_TYPE, wire_val);
    }
    fn get_wispr_bandwidth_max_down(&self) -> Option<u32> {
        self.get_attribute_as::<u32>(WISPR_BANDWIDTH_MAX_DOWN_TYPE)
    }
    fn set_wispr_bandwidth_max_down(&mut self, value: u32) {
        let wire_val = value;
        self.set_attribute_as::<u32>(WISPR_BANDWIDTH_MAX_DOWN_TYPE, wire_val);
    }
    fn get_wispr_session_terminate_time(&self) -> Option<String> {
        self.get_attribute_as::<String>(WISPR_SESSION_TERMINATE_TIME_TYPE)
    }
    fn set_wispr_session_terminate_time(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(WISPR_SESSION_TERMINATE_TIME_TYPE, wire_val);
    }
    fn get_wispr_session_terminate_end_of_day(&self) -> Option<String> {
        self.get_attribute_as::<String>(WISPR_SESSION_TERMINATE_END_OF_DAY_TYPE)
    }
    fn set_wispr_session_terminate_end_of_day(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(WISPR_SESSION_TERMINATE_END_OF_DAY_TYPE, wire_val);
    }
    fn get_wispr_billing_class_of_service(&self) -> Option<String> {
        self.get_attribute_as::<String>(WISPR_BILLING_CLASS_OF_SERVICE_TYPE)
    }
    fn set_wispr_billing_class_of_service(&mut self, value: impl Into<String>) {
        let wire_val: String = value.into();
        self.set_attribute_as::<String>(WISPR_BILLING_CLASS_OF_SERVICE_TYPE, wire_val);
    }
}
