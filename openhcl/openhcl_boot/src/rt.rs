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

/// Location of the HCL error information page (identity-mapped VA). `None`
/// means either no page was reserved by the loader or the panic handler
/// should not attempt to use it; in that case the handler falls back to the
/// standard enlightened-panic MSR path.
static ERROR_INFO_PAGE: SingleThreaded<Cell<Option<(IsolationType, u64)>>> =
    SingleThreaded(Cell::new(None));

/// Register the HCL error information page used by the panic handler to
/// report crashes to VMWP via the [`IGVM_VHS_ERROR_RANGE`] contract.
///
/// Must be called before anything that could panic. `info_page_va` is
/// identity-mapped so VA == PA.
pub fn init_error_info_page(isolation_type: IsolationType, info_page_va: u64) {
    ERROR_INFO_PAGE.set(Some((isolation_type, info_page_va)));
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

        // Try to publish the panic via the HCL error information page. On
        // success VMWP surfaces the message via MSVM_HCL_CRASH_REPORT when the
        // subsequent triple fault is caught; on failure fall back to the guest
        // crash MSRs so the host still sees *something*.
        #[cfg(target_arch = "x86_64")]
        if let Some((isolation_type, info_page)) = ERROR_INFO_PAGE.get() {
            if crate::arch::try_write_error_info_page(isolation_type, info_page, panic) {
                minimal_rt::arch::fault();
            }
        }

        // The stack is identity mapped.
        minimal_rt::enlightened_panic::report(*b"OHCLBOOT", panic, |va| Some(va as usize));
        minimal_rt::arch::fault();
    }
}
