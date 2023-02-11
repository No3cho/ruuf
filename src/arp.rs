//! Communicate using the Address Resolution Protocol.

use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::packet::arp::{
    ArpHardwareTypes, ArpOperation, ArpOperations, ArpPacket, MutableArpPacket,
};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::io::{Error, ErrorKind, Result};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

const MAC_ADDRESS_LENGTH: u8 = 6;
const IPV4_ADDRESS_LENGTH: u8 = 4;

/// Client for communication using the Address Resolution Protocol.
pub struct Client {
    /// Datalink channel for transmitting (using Ethernet).
    eth_tx: Box<dyn DataLinkSender>,

    /// Datalink channel for receiving (using Ethernet).
    eth_rx: Box<dyn DataLinkReceiver>,
}

impl Client {
    /// Create a new instance of [`Client`].
    ///
    /// # Error
    ///
    /// An error will be returned if creating an Ethernet channel failed.
    pub fn new(iface: &NetworkInterface) -> Result<Self> {
        match datalink::channel(iface, Default::default()) {
            Ok(Channel::Ethernet(eth_tx, eth_rx)) => Ok(Self { eth_tx, eth_rx }),
            Ok(_) => Err(Error::new(ErrorKind::Other, "Unknown channel type")),
            Err(err) => Err(err),
        }
    }

    /// Send an ARP message.
    ///
    /// # Error
    ///
    /// An error will be returned if sending the given message failed.
    pub fn send(&mut self, msg: Message) -> Result<()> {
        // Create Ethernet frame.
        //
        // Buffer is certainly large enough, so it is safe to unwrap.
        let eth_buf = &mut [0u8; 42];
        let mut eth_frm = MutableEthernetPacket::new(eth_buf).unwrap();
        eth_frm.set_source(msg.src.0);
        eth_frm.set_destination(msg.dest.0);
        eth_frm.set_ethertype(EtherTypes::Arp);

        // Place ARP message within Ethernet frame.
        let msg: ArpPacket = msg.into();
        eth_frm.set_payload(msg.packet());

        // Send message.
        self.eth_tx.send_to(eth_frm.packet(), None).unwrap()
    }

    /// Receive an ARP message satisfying the predicate, if any.
    ///
    /// A timeout will allow specification of the amount of time to try
    /// receiving an ARP message.
    ///
    /// # Error
    ///
    /// An error will be returned if receiving failed.
    pub fn recv<P>(
        &mut self,
        timeout: Option<Duration>,
        predicate: Option<P>,
    ) -> Result<Option<Message>>
    where
        P: Fn(Message) -> bool,
    {
        // Attempt to receive for either a caller-specified amount of time, or
        // the longest possible amount if none is specified.
        let start = Instant::now();
        while Instant::now().duration_since(start)
            < timeout.unwrap_or(Duration::from_millis(u64::MAX))
        {
            // Get buffer.
            let rx_buf = self.eth_rx.next()?;

            // Interpret as ARP response.
            let msg: Message =
                match ArpPacket::new(&rx_buf[MutableEthernetPacket::minimum_packet_size()..]) {
                    Some(res) => res.into(),
                    None => continue,
                };

            // Predicate.
            match predicate {
                Some(ref predicate) => {
                    if predicate(msg) {
                        return Ok(Some(msg));
                    }
                }
                None => return Ok(Some(msg)),
            }
        }

        Ok(None)
    }

    /// Resolve an IPv4 Address to a MAC address using ARP.
    ///
    /// # Error
    ///
    /// An error will be returned if sending or receiving failed.
    pub fn resolve(
        &mut self,
        src: (MacAddr, Ipv4Addr),
        target_ip_addr: Ipv4Addr,
        timeout: Option<Duration>,
    ) -> Result<Option<MacAddr>> {
        let req = Message::new(
            src,
            (MacAddr::broadcast(), target_ip_addr),
            ArpOperations::Request,
        );

        // Send request.
        self.send(req)?;

        // Receive reply.
        Ok(self
            .recv(
                timeout,
                Some(|msg: Message| {
                    msg.src.1 == target_ip_addr
                        && msg.dest.0 == src.0
                        && msg.op == ArpOperations::Reply
                }),
            )?
            .and_then(|msg| Some(msg.src.0)))
    }
}

/// High-level manner of representing an ARP Packet.
#[derive(Clone, Copy, Debug)]
pub struct Message {
    pub src: (MacAddr, Ipv4Addr),
    pub dest: (MacAddr, Ipv4Addr),
    pub op: ArpOperation,
}

impl Message {
    pub fn new(src: (MacAddr, Ipv4Addr), dest: (MacAddr, Ipv4Addr), op: ArpOperation) -> Self {
        Self { src, dest, op }
    }
}

impl<'p> From<ArpPacket<'p>> for Message {
    fn from(msg: ArpPacket<'p>) -> Self {
        Message::new(
            (msg.get_sender_hw_addr(), msg.get_sender_proto_addr()),
            (msg.get_target_hw_addr(), msg.get_target_proto_addr()),
            msg.get_operation(),
        )
    }
}

impl<'p> From<Message> for ArpPacket<'p> {
    fn from(msg: Message) -> Self {
        // Create ARP packet.
        //
        // Buffer is certainly large enough, so it is safe to unwrap.
        let arp_buf = &mut [0u8; 28];
        let mut arp_pkt = MutableArpPacket::new(arp_buf).unwrap();
        arp_pkt.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_pkt.set_protocol_type(EtherTypes::Ipv4);
        arp_pkt.set_hw_addr_len(MAC_ADDRESS_LENGTH);
        arp_pkt.set_sender_hw_addr(msg.src.0);
        arp_pkt.set_target_hw_addr(msg.dest.0);
        arp_pkt.set_proto_addr_len(IPV4_ADDRESS_LENGTH);
        arp_pkt.set_sender_proto_addr(msg.src.1);
        arp_pkt.set_target_proto_addr(msg.dest.1);
        arp_pkt.set_operation(msg.op);

        // Unwrapping is, once again, safe.
        ArpPacket::owned(arp_pkt.packet().to_vec()).unwrap()
    }
}
