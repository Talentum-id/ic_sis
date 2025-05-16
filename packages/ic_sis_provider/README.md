# ic_sis_provider

A ready-to-use canister for Sui wallet-based authentication on the Internet Computer.

## Overview

The `ic_sis_provider` canister implements the Sign-In with Sui (SIS) protocol to allow Internet Computer applications to authenticate users via their Sui wallets. It handles the entire authentication flow, from generating messages for the wallet to sign to creating and managing delegations for authenticated users.

## Features

- **Complete SIS Authentication**: Implements the full Sign-In with Sui protocol
- **Multiple Signature Schemes**: Supports Ed25519, Secp256k1, and Secp256r1 signature schemes
- **Delegation Management**: Handles delegation creation and verification
- **Principal Generation**: Creates consistent principals for Sui addresses
- **Configurable Parameters**: Customizable session and sign-in expiration times

## Installation

To add this canister to your Internet Computer project, update your `dfx.json` file:

```json
{
  "canisters": {
    "ic_sis_provider": {
      "type": "custom",
      "candid": "https://github.com/yourusername/ic-sis-provider/releases/latest/download/ic_sis_provider.did",
      "wasm": "https://github.com/yourusername/ic-sis-provider/releases/latest/download/ic_sis_provider.wasm.gz",
      "init_args": "(record { domain = \"yourdomain.com\"; uri = \"https://yourdomain.com\"; salt = \"your-secure-salt\"; network = opt \"mainnet\"; targets = null; sign_in_expires_in = null; session_expires_in = null; runtime_features = null })"
    }
  }
}
```

## Usage

### Initialization

The canister needs to be initialized with configuration parameters:

```
dfx deploy ic_sis_provider --argument '(record { domain = "yourdomain.com"; uri = "https://yourdomain.com"; salt = "your-secure-salt"; network = opt "mainnet"; targets = null; sign_in_expires_in = null; session_expires_in = null; runtime_features = null })'
```

### Authentication Flow

1. **Prepare Login**: Generate a message for the user's Sui wallet to sign
2. **Login**: Verify the signature and create a delegation
3. **Get Delegation**: Retrieve the delegation certificate for authentication

### Example Client Usage

```javascript
// Prepare login
const { sis_message, nonce } = await sisProvider.sis_prepare_login(suiAddress);

// Sign the message with the Sui wallet
const signature = await suiWallet.signMessage(sis_message);

// Login with the signature
const { user_canister_pubkey, expiration } = await sisProvider.sis_login(
  signature,
  suiAddress,
  sessionKey,
  nonce
);

// Get the delegation
const delegation = await sisProvider.sis_get_delegation(
  suiAddress,
  sessionKey,
  expiration
);

// Use the delegation to authenticate as the user
const identity = createIdentity(sessionKey, delegation);
```

## API Reference

### Core Authentication Methods

- `sis_prepare_login(address: text) -> (variant { Ok: PrepareLoginOkResponse; Err: text; })`
- `sis_login(signature: text, address: text, session_key: blob, nonce: text) -> (variant { Ok: LoginDetails; Err: text; })`
- `sis_get_delegation(address: text, session_key: blob, expiration: nat64) -> (variant { Ok: SignedDelegation; Err: text; })`

### Principal/Address Mappings

- `get_principal(address: text) -> (variant { Ok: blob; Err: text; })`
- `get_address(principal: blob) -> (variant { Ok: text; Err: text; })`
- `get_caller_address() -> (variant { Ok: text; Err: text; })`

## Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/ic-sis-provider
cd ic-sis-provider

# Build the canister
make build

# Deploy to the local replica
make deploy

# Or upgrade an existing deployment
make upgrade
```

## Development

```bash
# Start the local Internet Computer replica
dfx start --background

# Deploy with development settings
dfx deploy ic_sis_provider --argument '(record { domain = "localhost:8000"; uri = "http://localhost:8000"; salt = "dev-salt"; network = opt "devnet"; targets = null; sign_in_expires_in = null; session_expires_in = null; runtime_features = null })'

# Run tests
make test
```

## License

This project is licensed under the MIT License.