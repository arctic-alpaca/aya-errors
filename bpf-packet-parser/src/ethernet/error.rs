use crate::ethernet::header_values::EtherTypeParsingError;
use core::array::TryFromSliceError;
#[cfg(feature = "fmt")]
use core::fmt::{Debug, Display, Formatter};

#[cfg_attr(feature = "fmt", derive(Debug))]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum EthernetError {
    BpfCreation(EthernetBpfCreationError),
    BpfWithVlanCreation(EthernetBpfWithVlanCreationError),
    MatchEtherWithVlan(MatchEtherWithVlanError),
    GetHeader(GetHeaderError),
    GetFirstVlanParameter(GetFirstVlanParameterError),
    GetSecondVlanParameter(GetSecondVlanParameterError),
    CutFirstVlanTag(CutFirstVlanTagError),
    CutBothVlanTags(CutBothVlanTagsError),
}

#[cfg(feature = "fmt")]
impl Display for EthernetError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            EthernetError::BpfCreation(err) => {
                write!(f, "{err}")
            }
            EthernetError::BpfWithVlanCreation(err) => {
                write!(f, "{err}")
            }
            EthernetError::MatchEtherWithVlan(err) => {
                write!(f, "{err}")
            }
            EthernetError::GetHeader(err) => {
                write!(f, "{err}")
            }
            EthernetError::GetFirstVlanParameter(err) => {
                write!(f, "{err}")
            }
            EthernetError::GetSecondVlanParameter(err) => {
                write!(f, "{err}")
            }
            EthernetError::CutFirstVlanTag(err) => {
                write!(f, "{err}")
            }
            EthernetError::CutBothVlanTags(err) => {
                write!(f, "{err}")
            }
        }
    }
}

impl From<EthernetBpfCreationError> for EthernetError {
    fn from(value: EthernetBpfCreationError) -> Self {
        Self::BpfCreation(value)
    }
}

impl From<EthernetBpfWithVlanCreationError> for EthernetError {
    fn from(value: EthernetBpfWithVlanCreationError) -> Self {
        Self::BpfWithVlanCreation(value)
    }
}

impl From<MatchEtherWithVlanError> for EthernetError {
    fn from(value: MatchEtherWithVlanError) -> Self {
        Self::MatchEtherWithVlan(value)
    }
}

impl From<GetHeaderError> for EthernetError {
    fn from(value: GetHeaderError) -> Self {
        Self::GetHeader(value)
    }
}

impl From<GetFirstVlanParameterError> for EthernetError {
    fn from(value: GetFirstVlanParameterError) -> Self {
        Self::GetFirstVlanParameter(value)
    }
}

impl From<GetSecondVlanParameterError> for EthernetError {
    fn from(value: GetSecondVlanParameterError) -> Self {
        Self::GetSecondVlanParameter(value)
    }
}

impl From<CutFirstVlanTagError> for EthernetError {
    fn from(value: CutFirstVlanTagError) -> Self {
        Self::CutFirstVlanTag(value)
    }
}

impl From<CutBothVlanTagsError> for EthernetError {
    fn from(value: CutBothVlanTagsError) -> Self {
        Self::CutBothVlanTags(value)
    }
}

#[cfg(feature = "error_trait")]
impl core::error::Error for EthernetError {}

#[cfg_attr(feature = "fmt", derive(Debug))]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum EthernetBpfCreationError {
    NoRecognizedEtherType { ether_type: u16 },
    FrameTooShort { size: usize },
    BpfOutOfBounds,
    OutOfBoundsBufferAccess,
    CouldNotConvertSliceToArray,
}

impl From<EtherTypeParsingError> for EthernetBpfCreationError {
    fn from(value: EtherTypeParsingError) -> Self {
        match value {
            EtherTypeParsingError::NoRecognizedEtherType { ether_type } => {
                Self::NoRecognizedEtherType { ether_type }
            }
        }
    }
}

impl From<TryFromSliceError> for EthernetBpfCreationError {
    fn from(_: TryFromSliceError) -> Self {
        Self::CouldNotConvertSliceToArray
    }
}

#[cfg(feature = "fmt")]
impl Display for EthernetBpfCreationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            EthernetBpfCreationError::NoRecognizedEtherType { ether_type } => {
                write!(f, "No valid ether type, was: {ether_type:#06X}")
            }
            EthernetBpfCreationError::FrameTooShort { size } => {
                write!(
                    f,
                    "Ethernet frame expected to be larger than 14 bytes, was: {size}"
                )
            }
            EthernetBpfCreationError::OutOfBoundsBufferAccess => {
                write!(f, "Out of bound access, .get(...) returned None")
            }
            EthernetBpfCreationError::CouldNotConvertSliceToArray => {
                write!(f, "Could not convert slice to array")
            }
            EthernetBpfCreationError::BpfOutOfBounds => {
                write!(f, "Bpf out of bounds")
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl core::error::Error for EthernetBpfCreationError {}

#[cfg_attr(feature = "fmt", derive(Debug))]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum EthernetBpfWithVlanCreationError {
    NoRecognizedEtherType { ether_type: u16 },
    FrameTooShort { size: usize },
    BpfOutOfBounds,
    OutOfBoundsBufferAccess,
    CouldNotConvertSliceToArray,
}

impl From<TryFromSliceError> for EthernetBpfWithVlanCreationError {
    fn from(_: TryFromSliceError) -> Self {
        Self::CouldNotConvertSliceToArray
    }
}

impl From<MatchEtherWithVlanError> for EthernetBpfWithVlanCreationError {
    fn from(value: MatchEtherWithVlanError) -> Self {
        match value {
            MatchEtherWithVlanError::NoRecognizedEtherType { ether_type } => {
                Self::NoRecognizedEtherType { ether_type }
            }
            MatchEtherWithVlanError::OutOfBoundsBufferAccess => Self::OutOfBoundsBufferAccess,
            MatchEtherWithVlanError::CouldNotConvertSliceToArray => {
                Self::CouldNotConvertSliceToArray
            }
        }
    }
}

#[cfg(feature = "fmt")]
impl Display for EthernetBpfWithVlanCreationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoRecognizedEtherType { ether_type } => {
                write!(f, "No valid ether type, was: {ether_type:#06X}")
            }
            Self::FrameTooShort { size } => {
                write!(
                    f,
                    "Ethernet frame expected to be larger than 22 bytes, was: {size}"
                )
            }
            Self::OutOfBoundsBufferAccess => {
                write!(f, "Out of bound access, .get(...) returned None")
            }
            Self::CouldNotConvertSliceToArray => {
                write!(f, "Could not convert slice to array")
            }
            EthernetBpfWithVlanCreationError::BpfOutOfBounds => {
                write!(f, "Bpf out of bounds")
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl core::error::Error for EthernetBpfWithVlanCreationError {}

#[cfg_attr(feature = "fmt", derive(Debug))]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum MatchEtherWithVlanError {
    NoRecognizedEtherType { ether_type: u16 },
    OutOfBoundsBufferAccess,
    CouldNotConvertSliceToArray,
}

impl From<EtherTypeParsingError> for MatchEtherWithVlanError {
    fn from(value: EtherTypeParsingError) -> Self {
        match value {
            EtherTypeParsingError::NoRecognizedEtherType { ether_type } => {
                Self::NoRecognizedEtherType { ether_type }
            }
        }
    }
}

impl From<TryFromSliceError> for MatchEtherWithVlanError {
    fn from(_: TryFromSliceError) -> Self {
        Self::CouldNotConvertSliceToArray
    }
}

#[cfg(feature = "fmt")]
impl Display for MatchEtherWithVlanError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoRecognizedEtherType { ether_type } => {
                write!(f, "No valid ether type, was: {ether_type:#06X}")
            }
            Self::OutOfBoundsBufferAccess => {
                write!(f, "Out of bound access, .get(...) returned None")
            }
            Self::CouldNotConvertSliceToArray => {
                write!(f, "Could not convert slice to array")
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl core::error::Error for MatchEtherWithVlanError {}

#[cfg_attr(feature = "fmt", derive(Debug))]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum GetHeaderError {
    OutOfBoundsBufferAccess,
    CouldNotConvertSliceToArray,
}

impl From<TryFromSliceError> for GetHeaderError {
    fn from(_: TryFromSliceError) -> Self {
        Self::CouldNotConvertSliceToArray
    }
}

#[cfg(feature = "fmt")]
impl Display for GetHeaderError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutOfBoundsBufferAccess => {
                write!(f, "Out of bound access, .get(...) returned None")
            }
            Self::CouldNotConvertSliceToArray => {
                write!(f, "Could not convert slice to array")
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl core::error::Error for GetHeaderError {}

#[cfg_attr(feature = "fmt", derive(Debug))]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum GetFirstVlanParameterError {
    NotVlanTagged,
    OutOfBoundsBufferAccess,
    CouldNotConvertSliceToArray,
}

impl From<TryFromSliceError> for GetFirstVlanParameterError {
    fn from(_: TryFromSliceError) -> Self {
        Self::CouldNotConvertSliceToArray
    }
}

#[cfg(feature = "fmt")]
impl Display for GetFirstVlanParameterError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotVlanTagged => {
                write!(f, "Frame is not VLAN tagged")
            }
            Self::OutOfBoundsBufferAccess => {
                write!(f, "Out of bound access, .get(...) returned None")
            }
            Self::CouldNotConvertSliceToArray => {
                write!(f, "Could not convert slice to array")
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl core::error::Error for GetFirstVlanParameterError {}

#[cfg_attr(feature = "fmt", derive(Debug))]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum GetSecondVlanParameterError {
    NotVlanTagged,
    NotVlanDoubleTagged,
    OutOfBoundsBufferAccess,
    CouldNotConvertSliceToArray,
}

impl From<TryFromSliceError> for GetSecondVlanParameterError {
    fn from(_: TryFromSliceError) -> Self {
        Self::CouldNotConvertSliceToArray
    }
}

#[cfg(feature = "fmt")]
impl Display for GetSecondVlanParameterError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotVlanTagged => {
                write!(f, "Frame is not VLAN tagged")
            }
            Self::NotVlanDoubleTagged => {
                write!(f, "Frame is not double VLAN tagged")
            }
            Self::OutOfBoundsBufferAccess => {
                write!(f, "Out of bound access, .get(...) returned None")
            }
            Self::CouldNotConvertSliceToArray => {
                write!(f, "Could not convert slice to array")
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl core::error::Error for GetSecondVlanParameterError {}

#[cfg_attr(feature = "fmt", derive(Debug))]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum CutFirstVlanTagError {
    NotVlanTagged,
    CouldNotConvertSliceToArray,
}

impl From<TryFromSliceError> for CutFirstVlanTagError {
    fn from(_: TryFromSliceError) -> Self {
        Self::CouldNotConvertSliceToArray
    }
}

#[cfg(feature = "fmt")]
impl Display for CutFirstVlanTagError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotVlanTagged => {
                write!(f, "Frame is not VLAN tagged")
            }
            Self::CouldNotConvertSliceToArray => {
                write!(f, "Could not convert slice to array")
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl core::error::Error for CutFirstVlanTagError {}

#[cfg_attr(feature = "fmt", derive(Debug))]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum CutBothVlanTagsError {
    NotVlanTagged,
    NotVlanDoubleTagged,
    CouldNotConvertSliceToArray,
}

impl From<TryFromSliceError> for CutBothVlanTagsError {
    fn from(_: TryFromSliceError) -> Self {
        Self::CouldNotConvertSliceToArray
    }
}

#[cfg(feature = "fmt")]
impl Display for CutBothVlanTagsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotVlanTagged => {
                write!(f, "Frame is not VLAN tagged")
            }
            Self::NotVlanDoubleTagged => {
                write!(f, "Frame is not double VLAN tagged")
            }
            Self::CouldNotConvertSliceToArray => {
                write!(f, "Could not convert slice to array")
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl core::error::Error for CutBothVlanTagsError {}
