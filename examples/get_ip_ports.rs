extern crate netfilter_queue as nfq;

use nfq::ip::*;

fn main() {
    let _ = ip_ports(ProtocolFamily::INET, 0,
        &mut |qh: QueueHandle, netlink_header: &Header, ip_header: &IPPortHeader| -> Brake {
            let id = netlink_header.id();
            println!("Packet: {}\tProtocol: {}", id, ip_header.protocol() as u8);
            println!("{} -> {}", ip_header.source_socket(), ip_header.dest_socket());
            let _ = set_verdict(qh, id, Verdict::Accept);
            Brake::Continue
        }
    );
}
