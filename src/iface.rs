//! Get information of a network interface.

use pnet::datalink::{self, NetworkInterface};
use pnet::util::MacAddr;
use std::net::IpAddr;

/// Get the first network interface satisfying the predicate, if any.
pub fn get<P>(predicate: P) -> Option<NetworkInterface>
where
    P: Fn(&NetworkInterface) -> bool,
{
    datalink::interfaces()
        .into_iter()
        .find(|iface| predicate(iface))
}

/// Get the MAC address, if any, of the network interface.
pub const fn get_mac_addr(iface: &NetworkInterface) -> Option<MacAddr> {
    iface.mac
}

/// Get the first IP address satisfying the predicate, if any, of the network
/// interface.
pub fn get_ip_addr<P>(iface: &NetworkInterface, predicate: P) -> Option<IpAddr>
where
    P: Fn(IpAddr) -> bool,
{
    iface
        .ips
        .iter()
        .find(|net| predicate(net.ip()))
        .and_then(|net| Some(net.ip()))
}
