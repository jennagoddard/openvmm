// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(target_arch = "x86_64")]

//! x86_64 architecture-specific implementations.

mod address_space;
pub mod hypercall;
mod memory;
pub mod snp;
pub mod tdx;
mod vp;
mod vsm;

use crate::host_params::shim_params::IsolationType;
#[cfg(feature = "cvm_boot_log")]
use crate::host_params::shim_params::ShimParams;
pub use address_space::TdxHypercallPage;
pub use memory::setup_vtl2_memory;
pub use memory::verify_imported_regions_hash;
use safe_intrinsics::cpuid;
pub use vp::setup_vtl2_vp;
pub use vsm::get_isolation_type;
use x86defs::cpuid::CpuidFunction;

pub fn physical_address_bits(isolation: IsolationType) -> u8 {
    if isolation.is_hardware_isolated() {
        unimplemented!("can't trust host cpuid");
    }
    const DEFAULT_PHYSICAL_ADDRESS_SIZE: u8 = 32;

    let max_extended = {
        let result = cpuid(CpuidFunction::ExtendedMaxFunction.0, 0);
        result.eax
    };
    if max_extended >= CpuidFunction::ExtendedAddressSpaceSizes.0 {
        let result = cpuid(CpuidFunction::ExtendedAddressSpaceSizes.0, 0);
        (result.eax & 0xFF) as u8
    } else {
        DEFAULT_PHYSICAL_ADDRESS_SIZE
    }
}

/// Perform any architecture and isolation-specific initialization required
/// before the boot shim can use serial logging. For SNP, this sets up the
/// GHCB page so that IOIO exits can be used for port I/O.
#[cfg(feature = "cvm_boot_log")]
pub fn initialize_serial_io(p: &ShimParams) {
    if p.isolation_type == IsolationType::Snp {
        snp::Ghcb::initialize();
    }
}

/// Tear down architecture and isolation-specific state set up by
/// [`initialize_serial_io`]. For SNP, this restores the GHCB page to its
/// original private/accepted state.
#[cfg(feature = "cvm_boot_log")]
pub fn uninitialize_serial_io(p: &ShimParams) {
    if p.isolation_type == IsolationType::Snp {
        snp::Ghcb::uninitialize();
    }
}

// Entry point.
#[cfg(minimal_rt)]
core::arch::global_asm! {
    include_str!("entry.S"),
    relocate = sym minimal_rt::reloc::relocate,
    start = sym crate::rt::start,
    stack = sym crate::rt::STACK,
    STACK_COOKIE = const crate::rt::STACK_COOKIE,
    STACK_SIZE = const crate::rt::STACK_SIZE,
}

/// Write an [`loader_defs::hcl::HclErrorInformationPage`] describing the
/// panic to the HCL error information page so VMWP's triple-fault handler
/// can surface the message via `MSVM_HCL_CRASH_REPORT`.
///
/// Per VMWP's legacy `ErrorPage` contract the pages backing the error
/// range are host-owned/shared for the lifetime of the VM (VMWP retains
/// host visibility for them and does not inject them via
/// `SNP_LAUNCH_UPDATE` / into the Secure EPT). The loader also carves the
/// info page out of the initial page table and marks it
/// `Confidentiality::Shared`, so on SNP the C-bit is already clear on the
/// leaf PTE and on TDX the leaf PTE's physical address already has the
/// shared-GPA-boundary bit set. This function therefore just writes to
/// `info_page_va` — no runtime page-table manipulation is required.
///
/// The `_isolation_type` parameter is retained for future use (e.g. TDX
/// cache-attribute handling) but is currently unused.
#[cfg_attr(not(minimal_rt), expect(dead_code))]
pub fn try_write_error_info_page(
    _isolation_type: IsolationType,
    info_page_va: u64,
    panic: &core::panic::PanicInfo<'_>,
) -> bool {
    use core::fmt::Write;
    use loader_defs::hcl::HCL_ERROR_INFORMATION_STRING_SIZE;
    use loader_defs::hcl::HCL_ERROR_PAGE_DATA_VERSION_1;
    use loader_defs::hcl::HCL_TRIPLEFAULT_SIGNATURE;
    use loader_defs::hcl::HclErrorInformationPage;
    use loader_defs::hcl::HclErrorPageData;
    use zerocopy::IntoBytes;

    // Build the error information page on the stack, then copy it into the
    // info page. The leaf PTE was set up by the loader to be host-visible
    // (SNP: C-bit clear; TDX: shared-GPA-boundary bit set); on
    // non-hardware-isolated VMs there is no confidentiality metadata to
    // manage.
    let mut info = HclErrorInformationPage {
        stop_code: 0,
        parameter1: 0,
        parameter2: 0,
        parameter3: 0,
        parameter4: 0,
        signature: HCL_TRIPLEFAULT_SIGNATURE,
        data: HclErrorPageData {
            version: HCL_ERROR_PAGE_DATA_VERSION_1,
            message: [0; HCL_ERROR_INFORMATION_STRING_SIZE],
        },
        _reserved: [0; 4],
    };

    struct MessageWriter<'a> {
        buf: &'a mut [u8],
        pos: usize,
    }
    impl Write for MessageWriter<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let bytes = s.as_bytes();
            let remaining = self.buf.len() - self.pos;
            let to_copy = bytes.len().min(remaining);
            self.buf[self.pos..self.pos + to_copy].copy_from_slice(&bytes[..to_copy]);
            self.pos += to_copy;
            Ok(())
        }
    }

    // Reserve the last byte for null termination.
    let mut writer = MessageWriter {
        buf: &mut info.data.message[..HCL_ERROR_INFORMATION_STRING_SIZE - 1],
        pos: 0,
    };
    let _ = write!(writer, "{}", panic);

    // SAFETY: `info_page_va` is identity-mapped, page-aligned, and its
    // guest paging view was made host-visible by the loader.
    let dest = unsafe {
        core::slice::from_raw_parts_mut(info_page_va as *mut u8, hvdef::HV_PAGE_SIZE as usize)
    };
    dest.fill(0);
    let bytes = info.as_bytes();
    dest[..bytes.len()].copy_from_slice(bytes);

    true
}
