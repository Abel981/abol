use abol_core::packet::Packet;
pub const ERROR_CAUSE_TYPE: u8 = 101u8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCause {
    ResidualContextRemoved,
    InvalidEapPacket,
    UnsupportedAttribute,
    MissingAttribute,
    NasIdentificationMismatch,
    InvalidRequest,
    UnsupportedService,
    UnsupportedExtension,
    AdministrativelyProhibited,
    ProxyRequestNotRoutable,
    SessionContextNotFound,
    SessionContextNotRemovable,
    ProxyProcessingError,
    ResourcesUnavailable,
    RequestInitiated,
    Unknown(u32),
}
impl From<u32> for ErrorCause {
    fn from(v: u32) -> Self {
        match v {
            201u32 => Self::ResidualContextRemoved,
            202u32 => Self::InvalidEapPacket,
            401u32 => Self::UnsupportedAttribute,
            402u32 => Self::MissingAttribute,
            403u32 => Self::NasIdentificationMismatch,
            404u32 => Self::InvalidRequest,
            405u32 => Self::UnsupportedService,
            406u32 => Self::UnsupportedExtension,
            501u32 => Self::AdministrativelyProhibited,
            502u32 => Self::ProxyRequestNotRoutable,
            503u32 => Self::SessionContextNotFound,
            504u32 => Self::SessionContextNotRemovable,
            505u32 => Self::ProxyProcessingError,
            506u32 => Self::ResourcesUnavailable,
            507u32 => Self::RequestInitiated,
            other => Self::Unknown(other),
        }
    }
}
impl From<ErrorCause> for u32 {
    fn from(e: ErrorCause) -> Self {
        match e {
            ErrorCause::ResidualContextRemoved => 201u32,
            ErrorCause::InvalidEapPacket => 202u32,
            ErrorCause::UnsupportedAttribute => 401u32,
            ErrorCause::MissingAttribute => 402u32,
            ErrorCause::NasIdentificationMismatch => 403u32,
            ErrorCause::InvalidRequest => 404u32,
            ErrorCause::UnsupportedService => 405u32,
            ErrorCause::UnsupportedExtension => 406u32,
            ErrorCause::AdministrativelyProhibited => 501u32,
            ErrorCause::ProxyRequestNotRoutable => 502u32,
            ErrorCause::SessionContextNotFound => 503u32,
            ErrorCause::SessionContextNotRemovable => 504u32,
            ErrorCause::ProxyProcessingError => 505u32,
            ErrorCause::ResourcesUnavailable => 506u32,
            ErrorCause::RequestInitiated => 507u32,
            ErrorCause::Unknown(v) => v,
        }
    }
}
pub trait Rfc3576Ext {
    fn get_error_cause(&self) -> Option<ErrorCause>;
    fn set_error_cause(&mut self, value: ErrorCause);
}
impl Rfc3576Ext for Packet {
    fn get_error_cause(&self) -> Option<ErrorCause> {
        self.get_attribute_as::<u32>(ERROR_CAUSE_TYPE)
            .map(ErrorCause::from)
    }
    fn set_error_cause(&mut self, value: ErrorCause) {
        let wire_val: u32 = value.into();
        self.set_attribute_as::<u32>(ERROR_CAUSE_TYPE, wire_val);
    }
}
