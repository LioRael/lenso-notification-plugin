//! Transactional email dispatch role consumed by the Notification Plugin.

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

#[cfg(test)]
mod tests {
    #[test]
    fn domain_rejections_are_documented_as_pre_effect_only() {
        let contract = include_str!("../README.md");
        assert!(contract.contains("pre-effect rejections"));
        assert!(contract.contains("only before it has"));
        assert!(contract.contains("started any external effect"));
        assert!(contract.contains("terminal `delivery_unknown`"));
        assert!(contract.contains("never silently retries"));
    }
}
