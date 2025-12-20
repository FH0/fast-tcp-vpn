pub mod encapsulation;
pub mod routing;
pub mod session;
pub mod tunnel;
pub mod virtual_ip;

pub use encapsulation::{EncapsulatedData, EncapsulationError, EncapsulationHeader, Encapsulator};
pub use routing::{Route, RoutingError, RoutingTable};
pub use session::{
    Session, SessionConfig, SessionError, SessionId, SessionState, SessionStats,
};
pub use tunnel::{Tunnel, TunnelConfig, TunnelError, TunnelState, TunnelStats};
pub use virtual_ip::{IpAssignmentManager, IpPool, IpPoolError, VirtualIP};
