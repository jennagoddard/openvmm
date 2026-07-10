// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Logging support for the bootshim.
//!
//! The bootshim performs no filtering of its logging messages when running in
//! a confidential VM. This is because it runs before any keys can be accessed
//! or any guest code is executed, and therefore it can not leak anything
//! sensitive.

#[cfg(all(target_arch = "x86_64", feature = "cvm_boot_log"))]
use crate::arch::snp::SnpIoAccess;
#[cfg(all(target_arch = "x86_64", feature = "cvm_boot_log"))]
use crate::arch::tdx::TdxIoAccess;
use crate::host_params::shim_params::IsolationType;
use crate::single_threaded::SingleThreaded;
use core::cell::Cell;
use core::cell::RefCell;
use core::fmt;
use core::fmt::Write;
use host_fdt_parser::ComInfo;
use memory_range::MemoryRange;
#[cfg(target_arch = "x86_64")]
use minimal_rt::arch::InstrIoAccess;
use minimal_rt::arch::Serial;
use string_page_buf::StringBuffer;

enum Logger {
    #[cfg(target_arch = "x86_64")]
    Serial(Serial<InstrIoAccess>),
    #[cfg(target_arch = "aarch64")]
    #[expect(dead_code)]
    Serial(Serial),
    #[cfg(all(target_arch = "x86_64", feature = "cvm_boot_log"))]
    TdxSerial(Serial<TdxIoAccess>),
    #[cfg(all(target_arch = "x86_64", feature = "cvm_boot_log"))]
    SnpSerial(Serial<SnpIoAccess>),
    None,
}

impl Logger {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        match self {
            Logger::Serial(serial) => serial.write_str(s),
            #[cfg(all(target_arch = "x86_64", feature = "cvm_boot_log"))]
            Logger::TdxSerial(serial) => serial.write_str(s),
            #[cfg(all(target_arch = "x86_64", feature = "cvm_boot_log"))]
            Logger::SnpSerial(serial) => serial.write_str(s),
            Logger::None => Ok(()),
        }
    }
}

pub struct BootLogger {
    logger: SingleThreaded<RefCell<Logger>>,
    in_memory_logger: SingleThreaded<RefCell<Option<StringBuffer<'static>>>>,
    isolation_type: SingleThreaded<Cell<IsolationType>>,
}

pub static BOOT_LOGGER: BootLogger = BootLogger {
    logger: SingleThreaded(RefCell::new(Logger::None)),
    in_memory_logger: SingleThreaded(RefCell::new(None)),
    isolation_type: SingleThreaded(Cell::new(IsolationType::None)),
};

/// Store the isolation type so the panic handler can use it for last-resort
/// serial initialization.
pub fn boot_logger_set_isolation_type(isolation_type: IsolationType) {
    BOOT_LOGGER.isolation_type.set(isolation_type);
}

/// Initialize the in-memory log buffer. This range must be identity mapped, and
/// unused by anything else.
pub fn boot_logger_memory_init(buffer: MemoryRange) {
    if buffer.is_empty() {
        return;
    }

    let log_buffer_ptr = buffer.start() as *mut u8;
    // SAFETY: At file build time, this range is enforced to be unused by
    // anything else. The rest of the bootshim will mark this range as reserved
    // and not free to be used by anything else.
    //
    // The VA is valid as we are identity mapped.
    let log_buffer_slice =
        unsafe { core::slice::from_raw_parts_mut(log_buffer_ptr, buffer.len() as usize) };

    *BOOT_LOGGER.in_memory_logger.borrow_mut() = Some(
        StringBuffer::new(log_buffer_slice)
            .expect("log buffer should be valid from fixed at build config"),
    );
}

/// Initialize the runtime boot logger, for logging to serial or other outputs.
///
/// If a runtime logger was initialized, emit any in-memory log to the
/// configured runtime output.
pub fn boot_logger_runtime_init(isolation_type: IsolationType, com3_serial_available: ComInfo) {
    let mut logger = BOOT_LOGGER.logger.borrow_mut();

    *logger = match (isolation_type, com3_serial_available) {
        #[cfg(target_arch = "x86_64")]
        (IsolationType::None, ComInfo::Ns16550 { .. }) => {
            Logger::Serial(Serial::init(InstrIoAccess))
        }
        // TODO: fix the PL011 minimal_rt driver. Currently hangs even if
        // the MMIO address is correctly configured.
        // #[cfg(target_arch = "aarch64")]
        // (IsolationType::None, ComInfo::Pl011 { .. }) => Logger::Serial(Serial::init()),
        #[cfg(all(target_arch = "x86_64", feature = "cvm_boot_log"))]
        (IsolationType::Tdx, ComInfo::Ns16550 { .. }) => {
            Logger::TdxSerial(Serial::init(TdxIoAccess))
        }
        #[cfg(all(target_arch = "x86_64", feature = "cvm_boot_log"))]
        (IsolationType::Snp, ComInfo::Ns16550 { .. }) => {
            Logger::SnpSerial(Serial::init(SnpIoAccess))
        }
        _ => Logger::None,
    };

    // Emit any in-memory log to the runtime logger.
    if let Some(buf) = BOOT_LOGGER.in_memory_logger.borrow_mut().as_mut() {
        let _ = logger.write_str(buf.contents());
    }
}

impl Write for &BootLogger {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if let Some(buf) = self.in_memory_logger.borrow_mut().as_mut() {
            // Ignore the errors from the in memory logger.
            let _ = buf.append(s);
        }
        self.logger.borrow_mut().write_str(s)
    }
}

/// Attempt to flush the in-memory log buffer to serial on panic.
///
/// This is a best-effort fallback for cases where the runtime logger was never
/// initialized (e.g., a panic during device tree parsing before
/// `boot_logger_runtime_init` is called). It initializes a serial logger using
/// the stored isolation type and default COM3 settings, then flushes the
/// in-memory buffer.
///
/// This function is NOT safe against re-entrancy; it should only be called from
/// the panic handler as a last resort.
#[cfg_attr(not(minimal_rt), expect(dead_code))]
pub fn boot_logger_panic_flush() {
    let isolation_type = BOOT_LOGGER.isolation_type.get();

    // Use try_borrow_mut to avoid double-panic if we're already inside a log
    // call when the panic occurs.
    let Ok(mut logger) = BOOT_LOGGER.logger.try_borrow_mut() else {
        return;
    };

    if matches!(*logger, Logger::None) {
        *logger = match isolation_type {
            #[cfg(target_arch = "x86_64")]
            IsolationType::None => Logger::Serial(Serial::init(InstrIoAccess)),
            #[cfg(all(target_arch = "x86_64", feature = "cvm_boot_log"))]
            IsolationType::Tdx => Logger::TdxSerial(Serial::init(TdxIoAccess)),
            #[cfg(all(target_arch = "x86_64", feature = "cvm_boot_log"))]
            IsolationType::Snp => Logger::SnpSerial(Serial::init(SnpIoAccess)),
            _ => Logger::None,
        };
    }

    // Flush the in-memory log to the (possibly newly-initialized) serial.
    if let Ok(mut buf) = BOOT_LOGGER.in_memory_logger.try_borrow_mut() {
        if let Some(buf) = buf.as_mut() {
            let _ = logger.write_str(buf.contents());
        }
    }
}

impl log::Log for BootLogger {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        // TODO: filter level
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        let _ = writeln!(&*self, "[{}] {}", record.level(), record.args());
    }

    fn flush(&self) {}
}
