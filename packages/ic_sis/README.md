![Sign in with Sui for the Internet Computer](media/header.png)
[![Crate][crate-image]][crate-link] [![Docs][docs-image]][docs-link]

`ic_sis` is a Rust library that facilitates the integration of Sui wallet-based authentication with applications on the Internet Computer (ICP) platform. The library provides all necessary tools for integrating Sign-In with Sui (SIS) into ICP canisters, from generating SIS messages to creating delegate identities.

`ic_sis` enhances the interoperability between Sui and the Internet Computer platform, enabling developers to build applications that leverage the strengths of both platforms.

## Key Features

- **Sui Wallet Sign-In**: Enables Sui wallet sign-in for ICP applications. Sign in with any Sui wallet to generate an ICP identity and session.
- **Multiple Signature Schemes**: Supports various Sui signature schemes including Pure Ed25519, ECDSA Secp256k1, and ECDSA Secp256r1.
- **Session Identity Uniqueness**: Ensures that session identities are specific to each application's context, preventing cross-app identity misuse.
- **Consistent Principal Generation**: Guarantees that logging in with a Sui wallet consistently produces the same Principal, irrespective of the client used.
- **Direct Sui Address to Principal Mapping**: Creates a one-to-one correlation between Sui addresses and Principals within the scope of the current application.
- **Timebound Sessions**: Allows developers to set expiration times for sessions, enhancing security and control.
- **Intent Signing Support**: Implements Sui's intent signing protocol for secure transaction authentication.

## Table of Contents

- [Prebuilt `ic_sis_provider` canister](#prebuilt-ic_sis_provider-canister)
- [The SIS Standard](#the-sis-standard)
- [Login flow](#login-flow)
  - [SIS canister interface](#sis-canister-interface)
  - [`sis_prepare_login`](#sis_prepare_login)
  - [`sis_login`](#sis_login)
  - [`sis_get_delegation`](#sis_get_delegation)
- [Updates](#updates)
- [Contributing](#contributing)
- [License](#license)

## Prebuilt `ic_sis_provider` canister

While the `ic_sis` library can be integrated with any Rust-based ICP project, using the pre-built `ic_sis_provider` canister is the easiest way to integrate Sui wallet authentication into your application.

The canister is designed as a plug-and-play solution for developers, enabling easy integration into existing ICP applications with minimal coding requirements. By adding the pre-built `ic_sis_provider` canister to the `dfx.json` of an ICP project, developers can quickly enable Sui wallet-based authentication for their applications. The canister simplifies the authentication flow by managing the creation and verification of SIS messages and handling user session management.

## The SIS Standard

Sign-In with Sui (SIS) is a protocol for off-chain authentication of Sui accounts. The protocol is designed to enable Sui wallet-based authentication for applications on other platforms, such as the Internet Computer. At the core of the protocol is the SIS message, which is a signed message that contains the Sui address of the user and additional metadata. The SIS message is signed by the user's Sui wallet using one of the supported signature schemes and then sent to the application's backend. The backend verifies the signature and Sui address and then creates a session for the user.

The SIS protocol leverages Sui's multiple signature schemes, including:
- Pure Ed25519 (flag 0x00)
- ECDSA Secp256k1 (flag 0x01)
- ECDSA Secp256r1 (flag 0x02)

Each signature includes a scheme flag, the signature bytes, and the public key bytes, all properly formatted according to Sui's standards.

## Login flow

Creating a delegate identity using `ic_sis` is a three-step process that consists of the following steps:
1. Prepare login
2. Login
3. Get delegation

An implementing canister is free to implement these steps in any way it sees fit. It is recommended though that implementing canisters follow the login flow described below and implement the SIS canister interface.

The login flow is illustrated in the following diagram:

```text
                                ┌────────┐                                        ┌────────┐                              ┌────────┐
                                │Frontend│                                        │Canister│                              │SuiWallet│
   User                         └───┬────┘                                        └───┬────┘                              └────┬────┘
    │      Push login button       ┌┴┐                                                │                                        │
    │ ────────────────────────────>│ │                                                │                                        │
    │                              │ │                                                │                                        │
    │                              │ │          sis_prepare_login(sui_address)       ┌┴┐                                       │
    │                              │ │ ─────────────────────────────────────────────>│ │                                       │
    │                              │ │                                               └┬┘                                       │
    │                              │ │                OK, sis_message                 │                                        │
    │                              │ │ <─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─                                        │
    │                              │ │                                                │                                        │
    │                              │ │                                    Sign sis_message                                    ┌┴┐
    │                              │ │ ──────────────────────────────────────────────────────────────────────────────────────>│ │
    │                              │ │                                                │                                       │ │
    │                              │ │                  Ask user to confirm           │                                       │ │
    │ <───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────│ │
    │                              │ │                                                │                                       │ │
    │                              │ │                          OK                    │                                       │ │
    │  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ >│ │
    │                              │ │                                                │                                       └┬┘
    │                              │ │                                      OK, signature                                      │
    │                              │ │ <─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
    │                              │ │                                                │                                        │
    │                              │ │────┐                                           │                                        │
    │                              │ │    │ Generate random session_identity          │                                        │
    │                              │ │<───┘                                           │                                        │
    │                              │ │                                                │                                        │
    │                              │ │             sis_login(sui_address,             │                                        │
    │                              │ │          signature, session_identity)         ┌┴┐                                       │
    │                              │ │ ─────────────────────────────────────────────>│ │                                       │
    │                              │ │                                               │ │                                       │
    │                              │ │                                               │ │────┐                                  │
    │                              │ │                                               │ │    │ Verify signature with intent     │
    │                              │ │                                               │ │<───┘                                  │
    │                              │ │                                               │ │                                       │
    │                              │ │                                               │ │────┐                                  │
    │                              │ │                                               │ │    │ Prepare delegation               │
    │                              │ │                                               │ │<───┘                                  │
    │                              │ │                                               └┬┘                                       │
    │                              │ │     OK, canister_pubkey, delegation_expires    │                                        │
    │                              │ │ <─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─                                        │
    │                              │ │                                                │                                        │
    │                              │ │     sis_get_delegation(delegation_expires)    ┌┴┐                                       │
    │                              │ │ ─────────────────────────────────────────────>│ │                                       │
    │                              │ │                                               └┬┘                                       │
    │                              │ │                 OK, delegation                 │                                        │
    │                              │ │ <─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─                                        │
    │                              │ │                                                │                                        │
    │                              │ │────┐                                           │                                        │
    │                              │ │    │ Create delegation identity                │                                        │
    │                              │ │<───┘                                           │                                        │
    │                              └┬┘                                                │                                        │
    │ OK, logged in with            │                                                 │                                        │
    │ Principal niuiu-iuhbi...-oiu  │                                                 │                                        │
    │ <─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─                                                  │                                        │
  User                          ┌───┴────┐                                        ┌───┴────┐                              ┌────┴────┐
                                │Frontend│                                        │Canister│                              │SuiWallet│
                                └────────┘                                        └────────┘                              └─────────┘
```

### SIS canister interface

The SIS canister interface consists of three main methods:

### `sis_prepare_login`

- The `sis_prepare_login` method is called by the frontend application to initiate the login flow. The method takes the user's Sui address as a parameter and returns a SIS message together with a nonce. The frontend application uses the SIS message to prompt the user to sign the message with their Sui wallet.
- See: [`login::prepare_login`](src/login.rs)

### `sis_login`

- The `sis_login` method is called by the frontend application after the user has signed the SIS message. The method takes the user's Sui address, signature, session identity and nonce as parameters. The method verifies the signature using Sui's intent verification process and prepares the delegation to be fetched in the next step, the `sis_get_delegation` function.
- See: [`login::login`](src/login.rs)

### `sis_get_delegation`

- The `sis_get_delegation` method is called by the frontend application after a successful login. The method takes the delegation expiration time as a parameter and returns a delegation.
- The `sis_get_delegation` method is not mirrored by one function in the `ic_sis` library. The creation of delegate identities requires setting the certified data of the canister. This should not be done by the library, but by the implementing canister.
- Creating a delegate identity involves interacting with the following `ic_sis` functions: [`delegation::generate_seed`](src/delegation.rs),[`delegation::create_delegation`](src/delegation.rs), [`delegation::create_delegation_hash`](src/delegation.rs), [`delegation::witness`](src/delegation.rs), [`delegation::create_certified_signature`](src/delegation.rs).

## Updates

See the [CHANGELOG](CHANGELOG.md) for details on updates.

## Contributing

Contributions are welcome. Please submit your pull requests or open issues to propose changes or report bugs.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.

[crate-image]: https://img.shields.io/badge/crate-ic__sis-blue
[crate-link]: https://crates.io/crates/ic_sis
[docs-image]: https://img.shields.io/badge/docs-latest-blue
[docs-link]: https://docs.rs/ic_sis/