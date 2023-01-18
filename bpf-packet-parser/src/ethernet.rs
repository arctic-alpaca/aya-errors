mod error;
mod header_values;

pub use error::*;
pub use header_values::*;

#[cfg(feature = "fmt")]
use core::fmt::Debug;

// All ranges are [start..end).
// This means start is included, end is not included.
pub static DESTINATION_MAC_START: usize = 0;
pub static DESTINATION_MAC_END: usize = 6;
pub static SOURCE_MAC_START: usize = 6;
pub static SOURCE_MAC_END: usize = 12;
pub static ETHER_TYPE_START: usize = 12;
pub static ETHER_TYPE_END: usize = 14;
pub static SINGLE_TAGGED_ETHER_TYPE_START: usize = 16;
pub static SINGLE_TAGGED_ETHER_TYPE_END: usize = 18;
pub static DOUBLE_TAGGED_ETHER_TYPE_START: usize = 20;
pub static DOUBLE_TAGGED_ETHER_TYPE_END: usize = 22;
/// Payload starts at 14 if there is no Vlan tag, if there is one we add 4 bytes, if
/// the packet is double tagged, we add 2x4 bytes.
pub static PAYLOAD_START_NO_VLAN: usize = 14;
pub static FIRST_VLAN_TAG_ETHER_TYPE_START: usize = 12;
pub static FIRST_VLAN_TAG_ETHER_TYPE_END: usize = 14;
pub static FIRST_VLAN_TAG_PARAM_START: usize = 14;
pub static FIRST_VLAN_TAG_PARAM_END: usize = 16;
pub static SECOND_VLAN_TAG_ETHER_TYPE_START: usize = 16;
pub static SECOND_VLAN_TAG_ETHER_TYPE_END: usize = 18;
pub static SECOND_VLAN_TAG_PARAM_START: usize = 18;
pub static SECOND_VLAN_TAG_PARAM_END: usize = 20;

#[cfg_attr(feature = "fmt", derive(Debug))]
#[derive(Copy, Clone, PartialEq, Eq)]
// If the enum is not some 3u32/u63/usize, the BPF verfifier complains:
// "math between map_value pointer and register with unbounded min value is not allowed"
//#[repr(u64)]
pub enum Vlan {
    SingleTagged = 1,
    DoubleTagged = 2,
}

#[cfg_attr(feature = "fmt", derive(Debug))]
#[derive(PartialEq, Eq)]
pub struct EtherFrame<'a> {
    // size of 1B
    vlan: Option<Vlan>,
    // size of 2B
    ether_type: EtherType,
    // size of 16B
    headers: &'a mut [u8],
}

impl<'a> EtherFrame<'a> {
    #[cfg_attr(feature = "inline", inline(always))]
    pub fn new_bpf(
        buf: &'a mut [u8],
        end: usize,
    ) -> Result<(Self, &mut [u8]), EthernetBpfCreationError> {
        // We read at most the first 14 bytes of the frame:
        // 6 bytes dst MAC
        // 6 bytes src MAC
        // 2 bytes ether type
        // ------------------
        // 14 bytes total

        if end < buf.as_ptr() as usize + 14 {
            return Err(EthernetBpfCreationError::BpfOutOfBounds);
        }

        if buf.len() < 14 {
            return Err(EthernetBpfCreationError::FrameTooShort { size: buf.len() });
        }

        let value = u16::from_be_bytes(
            buf.get(ETHER_TYPE_START..ETHER_TYPE_END)
                .ok_or(EthernetBpfCreationError::OutOfBoundsBufferAccess)?
                .try_into()?,
        );

        let ether_type = EtherType::lookup(value)?;
        let (headers, payload) = buf.split_at_mut(14);

        Ok((
            EtherFrame {
                vlan: None,
                ether_type,
                headers,
            },
            payload,
        ))
    }

    #[cfg_attr(feature = "inline", inline(always))]
    pub fn new_bpf_with_vlan(
        buf: &'a mut [u8],
        end: usize,
    ) -> Result<(Self, &mut [u8]), EthernetBpfWithVlanCreationError> {
        // We read at most the first 22 bytes of the frame:
        // 6 bytes dst MAC
        // 6 bytes src MAC
        // 4 bytes 1. VLAN tag
        // 4 bytes 2. VLAN tag
        // 2 bytes ether type
        // ------------------
        // 22 bytes total

        if end < buf.as_ptr() as usize + 22 {
            return Err(EthernetBpfWithVlanCreationError::BpfOutOfBounds);
        }

        if buf.len() < 22 {
            return Err(EthernetBpfWithVlanCreationError::FrameTooShort { size: buf.len() });
        }

        let (ether_type, vlan_tag_len, vlan) = Self::match_ether_type_with_vlan(buf)?;

        let (headers, payload) = buf.split_at_mut(PAYLOAD_START_NO_VLAN + vlan_tag_len);

        Ok((
            EtherFrame {
                vlan,
                ether_type,
                headers,
            },
            payload,
        ))
    }

    #[cfg_attr(feature = "inline", inline(always))]
    pub fn get_vlan(&self) -> Option<Vlan> {
        self.vlan
    }

    #[cfg_attr(feature = "inline", inline(always))]
    fn match_ether_type_with_vlan(
        frame: &[u8],
    ) -> Result<(EtherType, usize, Option<Vlan>), MatchEtherWithVlanError> {
        let mut vlan = None;
        // Length of the VLAN tags.
        let mut vlan_tag_len = 0;

        let ether_type = match <&[u8] as TryInto<&[u8; 10]>>::try_into(
            frame
                .get(ETHER_TYPE_START..ETHER_TYPE_START + 10)
                .ok_or(MatchEtherWithVlanError::OutOfBoundsBufferAccess)?,
        )? {
            [0x81, 0x00, _, _, x, y, _, _, _, _] => {
                vlan = Some(Vlan::SingleTagged);
                vlan_tag_len = 4;

                EtherType::lookup(u16::from_be_bytes([*x, *y]))?
            }
            [0x88, 0xA8, _, _, 0x81, 0x00, _, _, x, y] => {
                vlan = Some(Vlan::DoubleTagged);
                vlan_tag_len = 8;

                EtherType::lookup(u16::from_be_bytes([*x, *y]))?
            }
            [x, y, _, _, _, _, _, _, _, _] => EtherType::lookup(u16::from_be_bytes([*x, *y]))?,
        };
        Ok((ether_type, vlan_tag_len, vlan))
    }

    #[cfg_attr(feature = "inline", inline(always))]
    pub fn get_destination(&self) -> Result<&[u8; 6], GetHeaderError> {
        Ok(self
            .headers
            .get(DESTINATION_MAC_START..DESTINATION_MAC_END)
            .ok_or(GetHeaderError::OutOfBoundsBufferAccess)?
            .try_into()?)
    }

    #[cfg_attr(feature = "inline", inline(always))]
    pub fn get_source(&self) -> Result<&[u8; 6], GetHeaderError> {
        Ok(self
            .headers
            .get(SOURCE_MAC_START..SOURCE_MAC_END)
            .ok_or(GetHeaderError::OutOfBoundsBufferAccess)?
            .try_into()?)
    }

    #[cfg_attr(feature = "inline", inline(always))]
    pub fn get_typed_ether_type(&self) -> EtherType {
        self.ether_type
    }

    #[cfg_attr(feature = "inline", inline(always))]
    pub fn get_ether_type(&self) -> Result<&[u8; 2], GetHeaderError> {
        if let Some(vlan_tag) = self.vlan {
            match vlan_tag {
                Vlan::SingleTagged => Ok(self
                    .headers
                    .get(SINGLE_TAGGED_ETHER_TYPE_START..SINGLE_TAGGED_ETHER_TYPE_END)
                    .ok_or(GetHeaderError::OutOfBoundsBufferAccess)?
                    .try_into()?),
                Vlan::DoubleTagged => Ok(self
                    .headers
                    .get(DOUBLE_TAGGED_ETHER_TYPE_START..DOUBLE_TAGGED_ETHER_TYPE_END)
                    .ok_or(GetHeaderError::OutOfBoundsBufferAccess)?
                    .try_into()?),
            }
        } else {
            Ok(self
                .headers
                .get(ETHER_TYPE_START..ETHER_TYPE_END)
                .ok_or(GetHeaderError::OutOfBoundsBufferAccess)?
                .try_into()?)
        }
    }
}
