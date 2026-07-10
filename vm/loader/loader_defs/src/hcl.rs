// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HCL (Hyper-V Compatibility Layer) error page definitions.
//!
//! These types mirror the C definitions in the legacy Hyper-V `HclDefs.h`
//! header and describe the contract between OpenHCL and VMWP for reporting
//! VTL2 crashes.
//!
//! The IGVM file reserves a two-page "error range" (see
//! `BootPageAcceptance::ErrorPage`). VMWP discovers the range GPA from the
//! `IGVM_VHS_ERROR_RANGE` directive. On a triple fault in VTL2, VMWP reads a
//! [`HclErrorInformationPage`] from the second page of the range and, if the
//! [`signature`](HclErrorInformationPage::signature) matches
//! [`HCL_TRIPLEFAULT_SIGNATURE`], surfaces the embedded message via
//! `MSVM_HCL_CRASH_REPORT` and `VmTripleFaultMessage`.

use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

/// Number of 4K pages in an HCL error range. Page 0 is the doorbell page
/// (unused by OpenHCL today) and page 1 is the [`HclErrorInformationPage`].
pub const HCL_ERROR_RANGE_PAGE_COUNT: u64 = 2;

/// Maximum message length in bytes stored in [`HclErrorPageData::message`].
pub const HCL_ERROR_INFORMATION_STRING_SIZE: usize = 256;

/// Version stamp for [`HclErrorPageData::version`]. Major=1, minor=0.
pub const HCL_ERROR_PAGE_DATA_VERSION_1: u32 = 0x0100;

/// Signature written to [`HclErrorInformationPage::signature`] when the
/// contents describe a triple fault crash. Numeric value of the ASCII string
/// `"HCLFAULT"` interpreted as a big-endian `u64`.
pub const HCL_TRIPLEFAULT_SIGNATURE: u64 = 0x48434C4641554C54;

/// Versioned data portion of [`HclErrorInformationPage`]. Layout matches C
/// `HCL_ERROR_PAGE_DATA` in `HclDefs.h`.
#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, FromBytes, Immutable, KnownLayout)]
pub struct HclErrorPageData {
    /// Data-format version. Use [`HCL_ERROR_PAGE_DATA_VERSION_1`].
    pub version: u32,
    /// Null-terminated ASCII crash message. Longer messages must be truncated.
    pub message: [u8; HCL_ERROR_INFORMATION_STRING_SIZE],
}

/// Layout of the error information page consumed by VMWP's triple-fault
/// handler. Layout matches C `HCL_ERROR_INFORMATION_PAGE` in `HclDefs.h`.
#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, FromBytes, Immutable, KnownLayout)]
pub struct HclErrorInformationPage {
    /// Bug-check style stop code. Zero for OpenHCL boot-shim panics today.
    pub stop_code: u64,
    /// Stop-code parameter 1.
    pub parameter1: u64,
    /// Stop-code parameter 2.
    pub parameter2: u64,
    /// Stop-code parameter 3.
    pub parameter3: u64,
    /// Stop-code parameter 4.
    pub parameter4: u64,
    /// Set to [`HCL_TRIPLEFAULT_SIGNATURE`] to tell VMWP the data section is
    /// valid and describes a triple fault.
    pub signature: u64,
    /// Versioned crash-message payload.
    pub data: HclErrorPageData,
}

static_assertions::const_assert_eq!(size_of::<HclErrorPageData>(), 260);
static_assertions::const_assert_eq!(size_of::<HclErrorInformationPage>(), 312);
