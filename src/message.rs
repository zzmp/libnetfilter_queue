//! Message parsing
//!
//! Analagous to <http://netfilter.org/projects/libnetfilter_queue/doxygen/group__Parsing.html>

use libc::*;
use std::ptr::null;
use error::*;
use util::*;
use ffi::*;
pub use ffi::nfqnl_msg_packet_hdr as Header;

/// Structs impl'ing `Payload` must be sized correctly for the payload data that mill be transmuted to it
pub trait Payload {}

/// The packet message
pub struct Message<'a> {
    /// A raw pointer to the queue data
    pub raw: *mut nfgenmsg,
    /// A raw pointer to the packet data
    pub ptr: *mut nfq_data,
    /// The `Message` header
    ///
    /// A verdict cannot be set without the packet's id
    /// parsed from the header.
    /// For convenience, the header is always parsed into the message.
    pub header: &'a Header
}

impl<'a> Drop for Message<'a> {
    fn drop(&mut self) {}
}

impl<'a> Message<'a> {
    #[doc(hidden)]
    pub fn new(raw: *mut nfgenmsg, ptr: *mut nfq_data) -> Result<Message<'a>, Error> {
        let header = unsafe {
            let ptr = nfq_get_msg_packet_hdr(ptr);
            match as_ref(&ptr) {
                Some(h) => h,
                None => return Err(error(Reason::GetHeader, "Failed to get header", None))
            }
        };
        Ok(Message {
            raw: raw,
            ptr: ptr,
            header: header
        })
    }

    /// Parse a sized `Payload` from the message
    ///
    /// The size of the `Payload` must be equal to the value that `handle.start` was called with.
    /// The best way to do this is with the `queue_builder.set_copy_mode_sized_to_payload`
    /// and `handle.start_sized_to_payload` methods.
    /// See `examples/get_addrs.rs`.
    pub unsafe fn payload<A: Payload>(&self) -> Result<&A, Error> {
        let data: *const A = null();
        let ptr: *mut *mut A = &mut (data as *mut A);
        let _ = match nfq_get_payload(self.ptr, ptr as *mut *mut c_uchar) {
            -1 => return Err(error(Reason::GetPayload, "Failed to get payload", Some(-1))),
            _ => ()
        };
        match as_ref(&data) {
            Some(payload) => Ok(payload),
            None => Err(error(Reason::GetPayload, "Failed to get payload", None))
        }
    }
}
