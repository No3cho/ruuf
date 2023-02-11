//! Interface with the Command-Line.

use crate::iface;

use pnet::datalink::NetworkInterface;
use std::net::Ipv4Addr;
use std::time::Duration;
use structopt::StructOpt;

#[derive(StructOpt)]
pub struct Command {
    /// Despoof upon receiving SIGINT (CTRL+C), SIGTERM or SIGHUP.
    #[structopt(short = "d")]
    should_despoof: bool,

    /// Network interface to use.
    #[structopt(short, parse(try_from_str = parse_iface))]
    iface: Option<NetworkInterface>,

    /// ARP resolution timeout, in milliseconds.
    #[structopt(short = "u", default_value = "10000", parse(try_from_str = parse_millis))]
    resolve_timeout: Duration,

    /// ARP spoofing interval, in milliseconds.
    #[structopt(short = "j", default_value = "10000", parse(try_from_str = parse_millis))]
    spoof_interval: Duration,

    /// Spoof as the machine with this IPv4 address.
    #[structopt(short)]
    target_ip_addr: Ipv4Addr,

    /// Poison the ARP Cache of the machine with this IPv4 address.
    #[structopt(short)]
    victim_ip_addr: Ipv4Addr,
}

impl Command {
    /// Despoof upon receiving SIGINT (CTRL+C), SIGTERM or SIGHUP.
    pub const fn should_despoof(&self) -> bool {
        self.should_despoof
    }

    /// Network interface to use.
    pub const fn iface(&self) -> Option<&NetworkInterface> {
        self.iface.as_ref()
    }

    /// ARP resolution timeout, in milliseconds.
    pub const fn resolve_timeout(&self) -> Duration {
        self.resolve_timeout
    }

    /// ARP spoofing interval, in milliseconds.
    pub const fn spoof_interval(&self) -> Duration {
        self.spoof_interval
    }

    /// Spoof as the machine with this IPv4 address.
    pub const fn target_ip_addr(&self) -> Ipv4Addr {
        self.target_ip_addr
    }

    /// Poison the ARP Cache of the machine with this IPv4 address.
    pub const fn victim_ip_addr(&self) -> Ipv4Addr {
        self.victim_ip_addr
    }
}

fn parse_iface(name: &str) -> Result<NetworkInterface, &'static str> {
    iface::get(|iface| !iface.is_loopback() && iface.is_up() && iface.name == name)
        .ok_or("No usuable network interface found by given name")
}

fn parse_millis(millis: &str) -> Result<Duration, &'static str> {
    millis
        .parse()
        .map(Duration::from_millis)
        .map_err(|_| "No unsigned 64 bit integer provided")
}
