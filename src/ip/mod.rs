#![allow(missing_docs)]

mod protocol;

use libc::c_int;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::ptr;
use std::mem;
use num::traits::PrimInt;
pub use handle::*;
pub use queue::*;
pub use message::*;
pub use error::*;
pub use self::protocol::Protocol;

/// A `Payload` to fetch and parse an IP packet header
pub struct IPHeader {
    pub version_and_header_raw: u8,
    pub dscp_raw: u8,
    pub total_length_raw: u16,
    pub id_raw: u16,
    pub flags_and_offset_raw: u16,
    pub ttl_raw: u8,
    pub protocol_raw: u8,
    pub checksum_raw: u16,
    pub saddr_raw: u32,
    pub daddr_raw: u32
}

pub struct IPPortHeader {
    pub header: IPHeader,
    pub sport_raw: u16,
    pub dport_raw: u16
}

impl Payload for IPHeader {}
impl Payload for IPPortHeader {}

impl IPHeader {
    #[inline]
    pub fn protocol(&self) -> Protocol {
        Protocol::from(u8::from_be(self.protocol_raw))
    }

    /// Parse the source address
    #[inline]
    pub fn source_ip(&self) -> Ipv4Addr {
        addr_to_ipv4(&self.saddr_raw)
    }

    /// Parse the destination address
    #[inline]
    pub fn dest_ip(&self) -> Ipv4Addr {
        addr_to_ipv4(&self.daddr_raw)
    }
}

impl IPPortHeader {
    #[inline]
    pub fn protocol(&self) -> Protocol {
        self.header.protocol()
    }

    #[inline]
    pub fn source_ip(&self) -> Ipv4Addr {
        self.header.source_ip()
    }

    #[inline]
    pub fn dest_ip(&self) -> Ipv4Addr {
        self.header.dest_ip()
    }

    #[inline]
    pub fn source_socket(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.header.source_ip(), u16::from_be(self.sport_raw))
    }

    #[inline]
    pub fn dest_socket(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.header.dest_ip(), u16::from_be(self.dport_raw))
    }
}

#[inline]
fn addr_to_ipv4(src: &u32) -> Ipv4Addr {
    let octets: [u8; 4] = unsafe { mem::transmute(*src) };
    Ipv4Addr::new(u8::from_be(octets[0]),
                  u8::from_be(octets[1]),
                  u8::from_be(octets[2]),
                  u8::from_be(octets[3]))
}

struct IPHandler<'a> {
    relay: &'a mut FnMut(QueueHandle, &Header, &IPHeader) -> Brake
}
struct IPPortHandler<'a>{
    relay: &'a mut FnMut(QueueHandle, &Header, &IPPortHeader) -> Brake
}

impl<'a> PacketHandler for IPHandler<'a> {
    fn handle(&mut self, qh: QueueHandle, message: Result<&Message, &Error>) -> Brake {
        match message {
            Ok(m) => {
                let netlink_header = m.header;
                match unsafe { m.payload() } {
                    Ok(ip_header) => {
                        (self.relay)(qh, netlink_header, ip_header)
                    },
                    Err(err) => {
                        warn!("Failed to parse IP header: {}", err);
                        Brake::Continue
                    }
                }
            },
            Err(err) => {
                warn!("Received corrupted packet: {}", err);
                Brake::Continue
            }
        }
    }
}

impl<'a> PacketHandler for IPPortHandler<'a> {
    fn handle(&mut self, qh: QueueHandle, message: Result<&Message, &Error>) -> Brake {
        match message {
            Ok(m) => {
                let netlink_header = m.header;
                match unsafe { m.payload() } {
                    Ok(ip_port_header) => {
                        (self.relay)(qh, netlink_header, ip_port_header)
                    },
                    Err(err) => {
                        warn!("Failed to parse IP header and ports: {}", err);
                        Brake::Continue
                    }
                }
            },
            Err(err) => {
                warn!("Received corrupted packet: {}", err);
                Brake::Continue
            }
        }
    }
}

pub fn ip<'a>(protocol_family: ProtocolFamily, queue_num: u16,
        handler: &'a mut FnMut(QueueHandle, &Header, &IPHeader) -> Brake)
        -> Result<(), Error> {
    let mut handle = try!(Handle::new());
    try!(handle.bind(protocol_family));
    let mut queue = try!(handle.queue(0, IPHandler{ relay: handler }));
    let _ = try!(queue.set_mode_sized::<IPHeader>());
    info!("Listening for packets on queue {}", queue_num);
    handle.start_sized::<IPHeader>()
}

pub fn ip_ports<'a>(protocol_family: ProtocolFamily, queue_num: u16,
        handler: &'a mut FnMut(QueueHandle, &Header, &IPPortHeader) -> Brake)
        -> Result<(), Error> {
    let mut handle = try!(Handle::new());
    try!(handle.bind(protocol_family));
    let mut queue = try!(handle.queue(queue_num, IPPortHandler{ relay: handler }));
    let _ = try!(queue.set_mode_sized::<IPPortHeader>());
    info!("Listening for packets on queue {}", queue_num);
    handle.start_sized::<IPPortHeader>()
}

pub fn set_verdict(qh: QueueHandle, id: u32, verdict: Verdict) -> Result<c_int, Error> {
    Verdict::set_verdict(qh, id, verdict, 0, ptr::null())
}
