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

/// Attempt to make a crash page shared and report a crash with a message
/// that the hypervisor can read.
///
/// This is used in the panic handler for hardware-isolated (SNP/TDX) VMs.
/// The crash page must be identity-mapped and in a different 2MB PDE from
/// the currently executing code and stack, because the page-table update
/// clears the C/shared bit at PDE granularity.
///
/// Returns `true` if the crash was successfully reported with a readable
/// message. Returns `false` if sharing failed (caller should fall back to
/// reporting without a message).
#[cfg_attr(not(minimal_rt), expect(dead_code))]
pub fn try_report_crash_hw_isolated(
    isolation_type: IsolationType,
    crash_page_va: u64,
    panic: &core::panic::PanicInfo<'_>,
) -> bool {
    use core::fmt::Write;

    // Guard against the crash page sharing its 2MB PDE with our code or
    // stack. If it did, clearing the C-bit on the whole PDE would fault the
    // very code we're running.
    const LARGE_PAGE_MASK: u64 = !(x86defs::X64_LARGE_PAGE_SIZE - 1);
    let crash_2mb = crash_page_va & LARGE_PAGE_MASK;

    let code_addr: u64;
    // SAFETY: Reading RIP via a RIP-relative LEA to determine which 2MB page
    // the currently executing code is in.
    unsafe {
        core::arch::asm!("lea {}, [rip]", out(reg) code_addr, options(nostack, nomem));
    }
    if (code_addr & LARGE_PAGE_MASK) == crash_2mb {
        return false;
    }

    let stack_va: u64;
    // SAFETY: Reading RSP to determine which 2MB page the stack is in.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) stack_va, options(nostack, nomem));
    }
    if (stack_va & LARGE_PAGE_MASK) == crash_2mb {
        return false;
    }

    let shared = match isolation_type {
        // SAFETY: We verified the crash page is in a different 2MB PDE from
        // our code and stack, so modifying the PDE won't affect execution.
        IsolationType::Snp => unsafe { snp::Ghcb::try_make_page_shared_for_crash(crash_page_va) },
        IsolationType::Tdx => {
            let range =
                memory_range::MemoryRange::new(crash_page_va..crash_page_va + hvdef::HV_PAGE_SIZE);
            // SAFETY: Same PDE-isolation guarantee as above.
            unsafe { tdx::try_make_page_shared_for_crash(range) }
        }
        _ => return false,
    };

    if !shared {
        return false;
    }

    // Page contents are undefined after sharing; format the panic message
    // straight into the shared page.
    // SAFETY: crash_page_va is identity-mapped, page-aligned, and now shared.
    let crash_buf = unsafe {
        core::slice::from_raw_parts_mut(crash_page_va as *mut u8, hvdef::HV_PAGE_SIZE as usize)
    };
    crash_buf.fill(0);

    struct CrashBufWriter<'a> {
        buf: &'a mut [u8],
        pos: usize,
    }
    impl Write for CrashBufWriter<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let bytes = s.as_bytes();
            let remaining = self.buf.len() - self.pos;
            let to_copy = bytes.len().min(remaining);
            self.buf[self.pos..self.pos + to_copy].copy_from_slice(&bytes[..to_copy]);
            self.pos += to_copy;
            Ok(())
        }
    }

    let mut writer = CrashBufWriter {
        buf: crash_buf,
        pos: 0,
    };
    let _ = write!(writer, "{}", panic);
    let len = writer.pos;

    // The crash page is identity-mapped, so VA == PA.
    minimal_rt::enlightened_panic::report_raw(
        *b"OHCLBOOT",
        &writer.buf[..len],
        Some(crash_page_va as usize),
    );

    true
}
