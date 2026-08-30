//! Transactional notification business ledger for Lenso.

mod contracts;
mod domain;
mod error;
mod events;
mod migrations;
pub mod operator;
mod plugin;
mod public;
mod repository;
mod runtime;
mod snapshot;

pub use operator::{NotificationOperator, NotificationOperatorError};
pub use plugin::{NotificationConfig, NotificationConfigError};

#[cfg(test)]
mod postgres_tests;
