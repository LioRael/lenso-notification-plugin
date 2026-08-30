//! Notification delivery worker and receipt-observation role.

#[allow(unknown_lints)]
#[allow(
    clippy::chunks_exact_to_as_chunks,
    clippy::manual_div_ceil,
    clippy::manual_is_multiple_of,
    clippy::verbose_bit_mask
)]
mod generated {
    include!("generated.rs");
}

pub use generated::*;

/// Source request Schema used by conformance and package-boundary tests.
pub const OBSERVE_RECEIPT_REQUEST_SCHEMA_JSON: &str =
    include_str!("../schemas/observe-receipt-request.schema.json");
