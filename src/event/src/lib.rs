#[cfg(feature = "openapi")]
use poem_openapi::{Enum, Object, Union};

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "openapi", derive(Enum), oai(rename_all = "snake_case"))]
pub enum PortProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "openapi",
    derive(Union),
    oai(rename_all = "snake_case", discriminator_name = "type")
)]
pub enum Event {
    ListenPortAssignment(ListenPortAssignment),
    ListenPortShutdown(ListenPortShutdown),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(Object))]
pub struct ListenPortAssignment {
    pub proto: PortProtocol,
    pub guest_port: u16,
    pub port: u16,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(Object))]
pub struct ListenPortShutdown {
    pub proto: PortProtocol,
    pub guest_port: u16,
}
