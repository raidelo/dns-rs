//! Core types and parsing logic for the DNS protocol.
//!
//! This crate provides low-level building blocks for working with DNS messages
//! as defined in [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035).
//!
//! # Modules
//!
//! - [`errors`] — Error types for DNS message parsing and processing.
//! - [`header`] — DNS message header ([`header::DNSHeader`]) and flags ([`header::Flags`]).
//! - [`class`] — DNS record class ([`class::Class`]) and question class ([`class::QClass`]).
//! - [`type_`] — DNS record type ([`type_::Type`]) and question type ([`type_::QType`]).
//! - [`label`] — DNS label parsing and representation ([`label::Label`]).

pub mod class;
pub mod errors;
pub mod header;
pub mod label;
pub mod name;
pub mod type_;
