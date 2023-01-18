#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub dst: [u8; 6],
    pub src: [u8; 6],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
