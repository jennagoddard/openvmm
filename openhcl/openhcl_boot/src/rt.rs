// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Architecture-independent runtime support.

use crate::host_params::shim_params::IsolationType;
use crate::single_threaded::SingleThreaded;
use core::cell::Cell;

// This must match the hardcoded value set at the entry point in the asm.
pub(crate) const STACK_SIZE: usize = 32768;
pub(crate) const STACK_COOKIE: u32 = 0x30405060;

#[repr(C, align(16))]
pub struct Stack([u8; STACK_SIZE]);

pub static mut STACK: Stack = Stack([0; STACK_SIZE]);

/// Crash reporting state consumed by the panic handler on hardware-isolated
/// VMs. `None` means the panic handler will fall back to the standard
/// enlightened-panic path with no shared crash page.
static CRASH_INFO: SingleThreaded<Cell<Option<(IsolationType, u64)>>> =
    SingleThreaded(Cell::new(None));

/// Register a crash page that the panic handler can share with the hypervisor.
///
/// Must be called before anything that could panic. Only meaningful for
/// hardware-isolated VMs; other isolation types can skip calling this.
pub fn init_crash_reporting(isolation_type: IsolationType, crash_page_pa: u64) {
    CRASH_INFO.set(Some((isolation_type, crash_page_pa)));
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

        // For hardware-isolated VMs (SNP/TDX), try to make the crash page
        // shared so the hypervisor can read the panic message. The boot shim
        // has no secrets, so this is safe.
        #[cfg(target_arch = "x86_64")]
        if let Some((isolation_type, crash_page)) = CRASH_INFO.get() {
            if crate::arch::try_report_crash_hw_isolated(isolation_type, crash_page, panic) {
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
