//! [EIP-XXXX] constants for the modexp contract deployment at H*.
//!
//! At the H* hardfork, the modexp precompile at address `0x05` is replaced with deployed
//! EVM bytecode. This module provides the address and bytecode constants.
//!
//! [EIP-XXXX]: https://eips.ethereum.org/EIPS/eip-XXXX

use alloy_primitives::{address, Address, Bytes};

/// Address of the modexp precompile / deployed contract.
pub const MODEXP_ADDRESS: Address = address!("0x0000000000000000000000000000000000000005");

/// EVM bytecode deployed at [`MODEXP_ADDRESS`] at Osaka.
///
/// Placeholder — will be replaced with the real modexp contract bytecode once finalized.
pub static MODEXP_CONTRACT_CODE: Bytes = Bytes::from_static(&[0x00]);
