//! EVM precompile primitives
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

use pallet_evm_precompile_modexp::Modexp;
use pallet_evm_precompile_sha3fips::Sha3FIPS256;
use pallet_evm_precompile_simple::{ECRecover, ECRecoverPublicKey, Identity, Ripemd160, Sha256};
use precompile_utils::precompile_set::*;
use transporter_precompile::TransporterPrecompile;

type EthereumPrecompilesChecks = (AcceptDelegateCall, CallableByContract, CallableByPrecompile);

#[precompile_utils::precompile_name_from_address]
type PrecompilesAt<R> = (
    // Ethereum precompiles:
    // We allow DELEGATECALL to stay compliant with Ethereum behavior.
    PrecompileAt<AddressU64<1>, ECRecover, EthereumPrecompilesChecks>,
    PrecompileAt<AddressU64<2>, Sha256, EthereumPrecompilesChecks>,
    PrecompileAt<AddressU64<3>, Ripemd160, EthereumPrecompilesChecks>,
    PrecompileAt<AddressU64<4>, Identity, EthereumPrecompilesChecks>,
    PrecompileAt<AddressU64<5>, Modexp, EthereumPrecompilesChecks>,
    // Non-Frontier specific nor Ethereum precompiles :
    PrecompileAt<AddressU64<1024>, Sha3FIPS256, (CallableByContract, CallableByPrecompile)>,
    PrecompileAt<AddressU64<1025>, ECRecoverPublicKey, (CallableByContract, CallableByPrecompile)>,
    // Subspace specific precompiles
    PrecompileAt<
        AddressU64<2048>,
        TransporterPrecompile<R>,
        (CallableByContract, CallableByPrecompile),
    >,
);

/// The PrecompileSet installed in the EVM Domain runtime.
/// The following distribution has been decided for the precompiles
/// 0-1023: Ethereum Mainnet Precompiles
/// 1024-2047 Precompiles that are not in Ethereum Mainnet, and are not Subspace specific
/// 2048-4095 Subspace specific precompiles
pub type Precompiles<R> = PrecompileSetBuilder<
    R,
    (
        // Skip precompiles if out of range.
        PrecompilesInRangeInclusive<(AddressU64<1>, AddressU64<4095>), PrecompilesAt<R>>,
    ),
>;
