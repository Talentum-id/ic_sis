# ic_sis: Sign-In with Sui for Internet Computer

`ic_sis` is a Rust library that implements the Sign-In with Sui (SIS) protocol for Internet Computer Protocol (ICP) applications. This library enables secure authentication using Sui blockchain accounts.

## Features

- Secure authentication using Sui digital signatures
- Support for both Ed25519 and Secp256k1 signature schemes
- Session management with automatic expiration
- Delegation system compatible with Internet Computer authentication
- Certified maps for authenticated data structures

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
ic_sis = "0.1.0"
```

## Usage Example

```rust
use ic_sis::{init, sui::SuiAddress, settings::SettingsBuilder};
use candid::Principal;

// Initialize the library with settings
let settings = SettingsBuilder::new("example.com", "https://example.com", "my_salt")
    .statement("Sign in to Example App")
    .sign_in_expires_in(300_000_000_000) // 5 minutes
    .session_expires_in(1_800_000_000_000) // 30 minutes
    .targets(vec![Principal::from_text("<YOUR_CANISTER_ID>").unwrap()])
    .build()
    .unwrap();

init(settings).unwrap();

// Prepare login flow for a Sui address
let address = SuiAddress::new("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
let (message, nonce) = prepare_login(&address).unwrap();

// User signs the message...

// Verify signature and complete login
let login_details = login(
    &signature,
    &address,
    &public_key,
    session_key,
    &mut signature_map,
    &canister_id,
    &nonce,
);
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.