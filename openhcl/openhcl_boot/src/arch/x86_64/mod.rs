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
/// The crash page must be identity-mapped and in a different 2MB page from
/// the currently executing code and stack.
///
/// Returns `true` if the crash was successfully reported with a readable
/// message. Returns `false` if sharing failed (caller should fall back to
/// reporting without a message).
pub fn try_report_crash_hw_isolated(
    isolation_type: IsolationType,
    crash_page_va: u64,
    panic: &core::panic::PanicInfo<'_>,
) -> bool {
    use core::fmt::Write;

    // Verify the crash page is in a different 2MB page from our code and stack.
    // If it's in the same page, sharing it would destroy our ability to execute.
    const LARGE_PAGE_MASK: u64 = !(x86defs::X64_LARGE_PAGE_SIZE - 1);
    let crash_2mb = crash_page_va & LARGE_PAGE_MASK;

    let code_addr = try_report_crash_hw_isolated as *const () as u64;
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

    // Try to make the crash page shared so the hypervisor can read the message.
    // Each helper performs the full sequence (hypervisor notification + PTE
    // update + TLB flush).
    let shared = match isolation_type {
        // SAFETY: We verified the crash page is in a different 2MB page from
        // our code and stack, so modifying the PDE won't affect our execution.
        IsolationType::Snp => unsafe { snp::Ghcb::try_make_page_shared_for_crash(crash_page_va) },
        IsolationType::Tdx => {
            let range =
                memory_range::MemoryRange::new(crash_page_va..crash_page_va + hvdef::HV_PAGE_SIZE);
            // SAFETY: We verified the crash page is in a different 2MB page
            // from our code and stack.
            unsafe { tdx::try_make_page_shared_for_crash(range) }
        }
        _ => return false,
    };

    if !shared {
        return false;
    }

    // The page contents are undefined after sharing. Zero the crash page
    // and write the panic message.
    // SAFETY: crash_page_va is identity-mapped, page-aligned, and now shared.
    let crash_buf = unsafe { core::slice::from_raw_parts_mut(crash_page_va as *mut u8, 4096) };

    // Zero the page to clear any stale/garbage data.
    crash_buf.fill(0);

    // Format the panic message directly into the shared crash page. We use a
    // small stack buffer and copy in chunks to avoid placing a large allocation
    // on the limited boot shim stack (only 32KB total).
    struct CrashBufWriter {
        buf: *mut u8,
        pos: usize,
        cap: usize,
    }
    impl Write for CrashBufWriter {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let bytes = s.as_bytes();
            let remaining = self.cap - self.pos;
            let to_copy = bytes.len().min(remaining);
            if to_copy > 0 {
                // SAFETY: buf is valid for cap bytes and pos < cap.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        self.buf.add(self.pos),
                        to_copy,
                    );
                }
                self.pos += to_copy;
            }
            Ok(())
        }
    }

    let mut writer = CrashBufWriter {
        buf: crash_buf.as_mut_ptr(),
        pos: 0,
        cap: 4096,
    };
    let _ = write!(writer, "{}", panic);
    let len = writer.pos;

    // Report via crash MSRs. The PA is the same as the VA (identity mapped).
    minimal_rt::enlightened_panic::report_raw(
        *b"OHCLBOOT",
        &crash_buf[..len],
        Some(crash_page_va as usize),
    );

    true
}
