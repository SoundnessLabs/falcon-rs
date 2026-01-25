# Falcon-512 Smart Account Verifier for Soroban

A signature verifier contract compatible with [OpenZeppelin's Soroban Smart Accounts](https://github.com/OpenZeppelin/stellar-contracts/tree/main/packages/accounts). Lets you use **Falcon-512 post-quantum signatures** with Stellar account abstraction.

## Overview

A thin wrapper around the [Falcon-512 verifier](../soroban-falcon-verifier) that implements the verifier interface OpenZeppelin's Smart Accounts expect. With this, you can create smart accounts secured by post-quantum signatures.

## Deployed Contracts (Testnet)

| Contract | Address |
|----------|---------|
| **Falcon-512 Verifier** | `CCVZDNGKWJPRLOXS4CBOJ2HTYNIW4C3244GG2CAA5V7UIYOMTF355QR7` |
| **Falcon Smart Account** | `CCZYRK7TZK6POBS5NMUPYBC7HA6EI4WJLWXNZCRF656L3HFF3BX43QBG` |

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

### Deploy Your Own Instance

```bash
# Build the contract
cd soroban-falcon-smart-account
stellar contract build

# Deploy
stellar contract deploy \
  --wasm target/wasm32v1-none/release/soroban_falcon_smart_account.wasm \
  --source <YOUR_KEY> \
  --network testnet

# Initialize with a Falcon verifier contract address
stellar contract invoke \
  --id <YOUR_CONTRACT_ID> \
  --source <YOUR_KEY> \
  --network testnet \
  -- \
  initialize \
  --falcon_verifier <FALCON_VERIFIER_CONTRACT_ADDRESS>
```

### Use with Smart Accounts

When creating an OpenZeppelin Smart Account, configure an external signer using this verifier:

```rust
use soroban_sdk::{Address, Bytes};

// Create an external signer with Falcon
let falcon_sa_verifier = Address::from_string(&"CCVZDNGKWJPRLOXS4CBOJ2HTYNIW4C3244GG2CAA5V7UIYOMTF355QR7");
let falcon_pubkey: Bytes = /* 897-byte Falcon-512 public key */;

// Add to Smart Account context rule
Signer::External(falcon_sa_verifier, falcon_pubkey)
```

### Sign and Verify

```rust
// Off-chain: Sign the authorization hash with Falcon
// The `falcon` crate handles key generation and signing
use falcon::{Falcon512, KeyPair, SignatureFormat};

let keypair = KeyPair::<Falcon512>::generate()?;
let auth_hash: [u8; 32] = /* SHA-256 of authorization payload */;
let signature = keypair.sign(&auth_hash, SignatureFormat::Padded)?;

// On-chain: Smart Account **calls** this verifier
// verify(auth_hash, pubkey, signature) -> true/false
```

### Example of On-chain Verification with Rust SDK

```rust
// 1. Build transfer transaction
let invoke_args = InvokeContractArgs {
    contract_address: XLM_SAC,
    function_name: "transfer",
    args: [from: SMART_ACCOUNT, to: DESTINATION, amount: 10_000_000],
};

// 2. First simulation - get nonce and invocation
let sim1 = simulate_transaction(unsigned_tx);
let nonce = sim1.auth_entry.credentials.nonce;
let invocation = sim1.auth_entry.root_invocation;

// 3. Compute payload hash
let preimage = HashIdPreimageSorobanAuthorization {
    network_id: sha256(NETWORK_PASSPHRASE),
    nonce,
    signature_expiration_ledger: current_ledger + 100,
    invocation,
};
let payload_hash: [u8; 32] = sha256(preimage.to_xdr());

// 4. Sign with Falcon-512
let falcon_signature = keypair.sign(payload_hash); 

// 5. Build signed auth entry
let signed_auth = SorobanAuthorizationEntry {
    credentials: SorobanAddressCredentials {
        address: SMART_ACCOUNT,
        nonce,
        signature_expiration_ledger,
        signature: ScVal::Bytes(falcon_signature),
    },
    root_invocation: invocation,
};

// 6. re-simulate with signed auth
let tx_with_auth = build_tx_with_auth(signed_auth);
let sim2 = simulate_transaction(tx_with_auth);

// 7. Build final transaction with exact resources
let final_tx = Transaction {
    fee: base_fee + sim2.min_resource_fee,
    ext: TransactionExt::V1(sim2.transaction_data),
    operations: [invoke_op_with_signed_auth],
};

// 8. Sign envelope and submit
let signed_envelope = fee_payer.sign(final_tx);
submit(signed_envelope);
```

## Related

- [Falcon-512 Verifier](../soroban-falcon-verifier) - Core verification logic
- [OpenZeppelin Smart Accounts](https://github.com/OpenZeppelin/stellar-contracts/tree/main/packages/accounts) - Account abstraction framework
- [Falcon NIST Submission](https://falcon-sign.info/) - Falcon algorithm specification
- [Soroban Custom Accounts](https://developers.stellar.org/docs/build/guides/conventions/custom-account) - Stellar documentation
- [Complex Account Example](https://github.com/stellar/soroban-examples/blob/main/account/src/lib.rs) - Reference implementation

## License

MIT