#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use packet_parser::error::Error;
use packet_parser::ethernet::{EtherFrame, EtherType, EthernetBpfWithVlanCreationError};

#[xdp(name = "packet_parser_aya")]
pub fn packet_parser_aya(ctx: XdpContext) -> u32 {
    match try_packet_parser_aya(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_packet_parser_aya(ctx: XdpContext) -> Result<u32, Error> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = ctx.data_end() - ctx.data();

    let data = unsafe { core::slice::from_raw_parts_mut(start as *mut u8, len) };
    EtherFrame::new_bpf(data, ctx.data_end())?;

    match EtherFrame::new_bpf_with_vlan(data, ctx.data_end()) {
        Ok((ethernet_frame, _)) => {
            // The next two info! lines trigger "R1 type=map_value expected=ctx".
            // Commenting out one of them changes the behavior.
            let dst = ethernet_frame.get_destination()?;
            info!(&ctx, "Dst: {:mac}", dst);
            let ether_type = u16::from_be_bytes(*ethernet_frame.get_ether_type()?);
            info!(&ctx, "EtherType: {:X}", ether_type);

            match ethernet_frame.get_typed_ether_type() {
                EtherType::IpV4 => {
                    // Comment to trigger "jump out of range from insn"
                    info!(&ctx, "IpV4")
                }
                EtherType::Arp => {
                    info!(&ctx, "Arp");
                }
                EtherType::WakeOnLan => {}
                EtherType::Avtp => {}
                EtherType::Srp => {}
                EtherType::Rarp => {}
                EtherType::AppleTalk => {}
                EtherType::Aarp => {}
                EtherType::Slpp => {}
                EtherType::Vlacp => {}
                EtherType::Ipx => {}
                EtherType::QnxQnet => {}
                EtherType::IpV6 => {
                    info!(&ctx, "IpV6")
                }
                EtherType::EthernetFlowControl => {}
                EtherType::EthernetSlowProtocols => {}
                EtherType::CobraNet => {}
                EtherType::MplsUnicast => {}
                EtherType::MplsMulticast => {}
                EtherType::PppoeDiscoveryStage => {}
                EtherType::PppoeSessionStage => {}
                EtherType::HomePlug1_0Mme => {}
                EtherType::EapOverLan => {}
                EtherType::Profinet => {}
                EtherType::HyperScsi => {}
                EtherType::AtaOverEthernet => {}
                EtherType::EtherCat => {}
                EtherType::EthernetPowerlink => {}
                EtherType::Goose => {}
                EtherType::GseManagementServices => {}
                EtherType::Sv => {}
                EtherType::Lldp => {}
                EtherType::Sercos3 => {}
                EtherType::HomePlugGreenPhy => {}
                EtherType::MediaRedundancyProtocol => {}
                EtherType::MacSec => {}
                EtherType::Pbb => {}
                EtherType::Ptp => {}
                EtherType::NcSi => {}
                EtherType::Prp => {}
                EtherType::Fcoe => {}
                EtherType::Mediaxtream => {}
                EtherType::FcoeInitializationProtocol => {}
                EtherType::Roce => {}
                EtherType::Tte => {}
                EtherType::Hsr => {}
                EtherType::EthernetConfigurationTestingProtocol => {}
                EtherType::RTag => {}
                EtherType::EtherTypeErrorVariant => {}
            }
        }

        Err(err) => match err {
            EthernetBpfWithVlanCreationError::NoRecognizedEtherType { .. } => {
                info!(&ctx, "NoRecognizedEtherType")
            }

            EthernetBpfWithVlanCreationError::FrameTooShort { .. } => {
                info!(&ctx, "FrameTooShort")
            }
            EthernetBpfWithVlanCreationError::OutOfBoundsBufferAccess => {
                info!(&ctx, "OutOfBoundsBufferAccess")
            }
            EthernetBpfWithVlanCreationError::CouldNotConvertSliceToArray => {
                info!(&ctx, "CouldNotConvertSliceToArray")
            }
            EthernetBpfWithVlanCreationError::BpfOutOfBounds => {
                info!(&ctx, "BpfOutOfBounds")
            }
        },
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
