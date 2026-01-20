# Falcon-512 Smart Account Verifier for Soroban

A signature verifier contract compatible with [OpenZeppelin's Soroban Smart Accounts](https://github.com/OpenZeppelin/stellar-contracts/tree/main/packages/accounts) framework. This enables **post-quantum signature verification** using the Falcon-512 algorithm for Stellar account abstraction.

## Overview

This contract acts as a thin wrapper around the [Falcon-512 verifier](../soroban-falcon-verifier), implementing the verifier interface expected by OpenZeppelin's Smart Accounts. It enables users to create smart accounts that use post-quantum secure signatures.

### Architecture

```
┌─────────────────────┐     ┌──────────────────────┐     ┌─────────────────────┐
│    Smart Account    │────▶│  Falcon SA Verifier  │────▶│   Falcon Verifier   │
│  (OpenZeppelin)     │     │    (this contract)   │     │  (core verification)│
└─────────────────────┘     └──────────────────────┘     └─────────────────────┘
```

### Benefits

- **Post-Quantum Security**: Falcon-512 is NIST-selected for post-quantum cryptography
- **Small WASM Size**: Only ~8KB (delegates to external verifier)
- **Standards Compatible**: Works with OpenZeppelin Smart Accounts framework
- **Efficient**: ~400k instructions for verification (~0.4% of Soroban budget)

## Deployed Contracts (Testnet)

| Contract | Address |
|----------|---------|
| **Falcon SA Verifier** | `CABP7S4OHISZY37RSSCPIXXGQK6A3CA65BKUFL4ZU6J6CF55GANHXNZY` |
| **Falcon-512 Verifier** | `CCVZDNGKWJPRLOXS4CBOJ2HTYNIW4C3244GG2CAA5V7UIYOMTF355QR7` |

## Contract Interface

### Functions

| Function | Description |
|----------|-------------|
| `initialize(falcon_verifier: Address)` | Initialize with Falcon verifier contract address (call once) |
| `verify(payload, key_data, sig_data) -> bool` | Verify a Falcon-512 signature |
| `get_falcon_verifier() -> Address` | Get the configured Falcon verifier address |
| `validate_inputs(payload, key_data, sig_data) -> bool` | Pre-flight input validation |
| `get_expected_sizes() -> (u32, u32, u32, u32, u32)` | Get expected input sizes |

### Input Sizes

| Parameter | Size | Description |
|-----------|------|-------------|
| `payload` | Any (typically 32 bytes) | Message/hash being verified |
| `key_data` | 897 bytes | Falcon-512 public key |
| `sig_data` | 42-700 bytes | Falcon signature (666 bytes padded) |

## Usage

### 1. Deploy Your Own Instance

```bash
# Build the contract
cd soroban-falcon-smart-account
stellar contract build

# Deploy
stellar contract deploy \
  --wasm target/wasm32v1-none/release/soroban_falcon_smart_account.wasm \
  --source <YOUR_KEY> \
  --network testnet

# Initialize with Falcon verifier address
stellar contract invoke \
  --id <YOUR_CONTRACT_ID> \
  --source <YOUR_KEY> \
  --network testnet \
  -- \
  initialize \
  --falcon_verifier CCVZDNGKWJPRLOXS4CBOJ2HTYNIW4C3244GG2CAA5V7UIYOMTF355QR7
```

### 2. Use with Smart Accounts

When creating an OpenZeppelin Smart Account, configure an external signer using this verifier:

```rust
use soroban_sdk::{Address, Bytes};

// Create an external signer with Falcon
let falcon_sa_verifier = Address::from_string(&"CABP7S4OHISZY37RSSCPIXXGQK6A3CA65BKUFL4ZU6J6CF55GANHXNZY");
let falcon_pubkey: Bytes = /* 897-byte Falcon-512 public key */;

// Add to Smart Account context rule
Signer::External(falcon_sa_verifier, falcon_pubkey)
```

### 3. Sign and Verify

```rust
// Off-chain: Sign the authorization hash with Falcon
// The `falcon` crate handles key generation and signing
use falcon::{Falcon512, KeyPair, SignatureFormat};

let keypair = KeyPair::<Falcon512>::generate()?;
let auth_hash: [u8; 32] = /* SHA-256 of authorization payload */;
let signature = keypair.sign(&auth_hash, SignatureFormat::Padded)?;

// On-chain: Smart Account calls this verifier
// verify(auth_hash, pubkey, signature) -> true/false
```

### 4. CLI Verification Test

```bash
# Get expected sizes
stellar contract invoke \
  --id CABP7S4OHISZY37RSSCPIXXGQK6A3CA65BKUFL4ZU6J6CF55GANHXNZY \
  --network testnet \
  -- \
  get_expected_sizes

# Verify a signature (replace with actual hex values)
stellar contract invoke \
  --id CABP7S4OHISZY37RSSCPIXXGQK6A3CA65BKUFL4ZU6J6CF55GANHXNZY \
  --source demo \
  --network testnet \
  -- \
  verify \
  --payload <32_BYTE_HEX> \
  --key_data <897_BYTE_PUBKEY_HEX> \
  --sig_data <666_BYTE_SIGNATURE_HEX>
```

## Development

### Build

```bash
cd soroban-falcon-smart-account
stellar contract build
```

### Test

```bash
cargo test -p soroban-falcon-smart-account --features testutils
```

### Project Structure

```
soroban-falcon-smart-account/
├── Cargo.toml
├── README.md
├── src/
│   └── lib.rs          # Contract implementation
└── tests/
    ├── fixtures/       # Test vectors
    │   ├── test_pubkey.hex
    │   └── test_signature.hex
    └── integration.rs  # Integration tests
```

## Security Considerations

1. **Immutable Verifier**: Once deployed, the Falcon verifier address cannot be changed
2. **Cross-Contract Trust**: This contract trusts the configured Falcon verifier
3. **Post-Quantum**: Falcon-512 provides ~128 bits of post-quantum security
4. **Signature Formats**: Supports compressed, padded, and constant-time formats

## Related

- [Falcon-512 Verifier](../soroban-falcon-verifier) - Core verification logic
- [OpenZeppelin Smart Accounts](https://github.com/OpenZeppelin/stellar-contracts/tree/main/packages/accounts) - Account abstraction framework
- [Falcon NIST Submission](https://falcon-sign.info/) - Falcon algorithm specification

## License

MIT
