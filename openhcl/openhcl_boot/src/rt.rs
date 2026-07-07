// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Architecture-independent runtime support.

use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering::Relaxed;

// This must match the hardcoded value set at the entry point in the asm.
pub(crate) const STACK_SIZE: usize = 32768;
pub(crate) const STACK_COOKIE: u32 = 0x30405060;

#[repr(C, align(16))]
pub struct Stack([u8; STACK_SIZE]);

pub static mut STACK: Stack = Stack([0; STACK_SIZE]);

/// Isolation type stored for the panic handler.
/// 0 = None/Vbs, 1 = Snp, 2 = Tdx
static CRASH_ISOLATION_TYPE: AtomicU8 = AtomicU8::new(0);

/// Physical address of the crash page (identity-mapped, so VA = PA).
/// 0 means no crash page is available.
static CRASH_PAGE_ADDRESS: AtomicU64 = AtomicU64::new(0);

/// Initialize crash reporting state used by the panic handler.
///
/// This must be called as early as possible in boot (before anything that
/// could panic) to ensure the panic handler can report diagnostics for
/// hardware-isolated VMs.
pub fn init_crash_reporting(
    isolation_type: crate::host_params::shim_params::IsolationType,
    crash_page_pa: u64,
) {
    use crate::host_params::shim_params::IsolationType;
    let type_val = match isolation_type {
        IsolationType::Snp => 1u8,
        IsolationType::Tdx => 2u8,
        _ => 0u8,
    };
    CRASH_ISOLATION_TYPE.store(type_val, Relaxed);
    if crash_page_pa != 0 {
        CRASH_PAGE_ADDRESS.store(crash_page_pa, Relaxed);
    }
}

/// Validate the stack cookie is still present. Panics if overwritten.
pub fn verify_stack_cookie() {
    // SAFETY: It's possible we've overrun the stack at this point if any
    // previous stack frame was too large. But, we know the pointer is valid and
    // never came from a rust reference, and we're about to crash if the value
    // is bogus.
    unsafe {
        let stack_ptr = core::ptr::addr_of!(STACK).cast::<u32>();
        if core::ptr::read(stack_ptr) != STACK_COOKIE {
            panic!("Stack was overrun - check for large variables");
        }
    }
}

/// The entry point.
///
/// X64: The relative offset for shim parameters are passed in the rsi register.
/// rax contains the base address of where the shim was loaded at.
///
/// ARM64: The relative offset for shim parameters are passed in the x1 register.
/// x2 contains the base address of where the shim was loaded at.
///
/// # Safety
///
/// The caller must ensure that the passed shim_params_offset is the correct offset
/// from the shim base to the shim parameters.
#[cfg_attr(not(minimal_rt), expect(dead_code))]
pub unsafe extern "C" fn start(_: usize, shim_params_offset: isize) -> ! {
    crate::shim_main(shim_params_offset)
}

#[cfg(minimal_rt)]
mod instead_of_builtins {
    use super::*;

    #[panic_handler]
    fn panic(panic: &core::panic::PanicInfo<'_>) -> ! {
        log::error!("{panic}");

        let isolation_type = CRASH_ISOLATION_TYPE.load(Relaxed);
        let crash_page = CRASH_PAGE_ADDRESS.load(Relaxed);

        // For hardware-isolated VMs (SNP/TDX), try to make the crash page
        // shared so the hypervisor can read the panic message. The boot shim
        // has no secrets, so this is safe.
        #[cfg(target_arch = "x86_64")]
        if isolation_type != 0 && crash_page != 0 {
            use crate::host_params::shim_params::IsolationType;
            let iso = match isolation_type {
                1 => IsolationType::Snp,
                2 => IsolationType::Tdx,
                _ => IsolationType::None,
            };
            if crate::arch::try_report_crash_hw_isolated(iso, crash_page, panic) {
                minimal_rt::arch::fault();
            }
        }

        // Fall back to standard enlightened panic (works for non-isolated VMs,
        // or if sharing failed for isolated VMs).
        // The stack is identity mapped.
        minimal_rt::enlightened_panic::report(*b"OHCLBOOT", panic, |va| Some(va as usize));
        minimal_rt::arch::fault();
    }
}
