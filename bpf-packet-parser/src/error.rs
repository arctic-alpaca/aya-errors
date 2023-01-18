use crate::ethernet::EthernetError::{
    BpfCreation, BpfWithVlanCreation, CutBothVlanTags, CutFirstVlanTag, GetFirstVlanParameter,
    GetHeader, GetSecondVlanParameter, MatchEtherWithVlan,
};
use crate::ethernet::{
    CutBothVlanTagsError, CutFirstVlanTagError, EthernetBpfCreationError,
    EthernetBpfWithVlanCreationError, EthernetError, GetFirstVlanParameterError, GetHeaderError,
    GetSecondVlanParameterError, MatchEtherWithVlanError,
};
#[cfg(feature = "fmt")]
use core::fmt::{Debug, Display, Formatter};

#[cfg_attr(feature = "fmt", derive(Debug))]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Error {
    Ethernet(EthernetError),
}

#[cfg(feature = "fmt")]
impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Ethernet(err) => {
                write!(f, "{err}")
            }
        }
    }
}

impl From<EthernetError> for Error {
    fn from(value: EthernetError) -> Self {
        Self::Ethernet(value)
    }
}

impl From<EthernetBpfCreationError> for Error {
    fn from(value: EthernetBpfCreationError) -> Self {
        Self::Ethernet(BpfCreation(value))
    }
}

impl From<EthernetBpfWithVlanCreationError> for Error {
    fn from(value: EthernetBpfWithVlanCreationError) -> Self {
        Self::Ethernet(BpfWithVlanCreation(value))
    }
}

impl From<MatchEtherWithVlanError> for Error {
    fn from(value: MatchEtherWithVlanError) -> Self {
        Self::Ethernet(MatchEtherWithVlan(value))
    }
}

impl From<GetHeaderError> for Error {
    fn from(value: GetHeaderError) -> Self {
        Self::Ethernet(GetHeader(value))
    }
}

impl From<GetFirstVlanParameterError> for Error {
    fn from(value: GetFirstVlanParameterError) -> Self {
        Self::Ethernet(GetFirstVlanParameter(value))
    }
}

impl From<GetSecondVlanParameterError> for Error {
    fn from(value: GetSecondVlanParameterError) -> Self {
        Self::Ethernet(GetSecondVlanParameter(value))
    }
}

impl From<CutFirstVlanTagError> for Error {
    fn from(value: CutFirstVlanTagError) -> Self {
        Self::Ethernet(CutFirstVlanTag(value))
    }
}

impl From<CutBothVlanTagsError> for Error {
    fn from(value: CutBothVlanTagsError) -> Self {
        Self::Ethernet(CutBothVlanTags(value))
    }
}

#[cfg(feature = "error_trait")]
impl core::error::Error for Error {}
