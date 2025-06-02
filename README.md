![Sign in with Sui for the Internet Computer](/media/header.png)

`ic-sis` is a project that enables Sui wallet-based authentication for applications on the [Internet Computer](https://internetcomputer.org) (ICP). The goal of the project is to enhance the interoperability between Sui and ICP, enabling developers to build applications that leverage the strengths of both platforms.

## Features

- **Sui Wallet Sign-In**: Enables Sui wallet sign-in for ICP applications. Sign in with any Sui wallet to generate an ICP identity and session.

- **Session Identity Uniqueness**: Ensures that session identities are specific to each application's context, preventing cross-app identity misuse.

- **Consistent Principal Generation**: Guarantees that logging in with a Sui wallet consistently produces the same Principal, irrespective of the client used.

- **Direct Sui Address to Principal Mapping**: Creates a one-to-one correlation between Sui addresses and Principals within the scope of the current application.

- **Timebound Sessions**: Allows developers to set expiration times for sessions, enhancing security and control.

- **Multiple Signature Schemes**: Supports various Sui signature schemes including Pure Ed25519, ECDSA Secp256k1, and ECDSA Secp256r1.

- **Prebuilt Identity Provider**: Provides a prebuilt canister that can be integrated into any Internet Computer application, independent of the application's programming language.

## Usage

Developers have two options to use SIS in their ICP applications:

1. **Use the prebuilt [ic_sis_provider](https://github.com/Talentum-id/ic_sis/tree/master/packages/ic_sis_provider) canister**: This is the easiest way to integrate SIS into an Internet Computer application. The pre-built canister is added to the project `dfx.json` and then configured to meet the needs of the application. `ic_sis_provider` can be added to any ICP application, independent of the application's programming language.

2. **Use the [ic_sis](https://crates.io/crates/ic_sis) library**: This allows developers full control over the SIS integration. The `ic_sis` Rust library provides all the necessary tools for integrating SIS into ICP canisters.

### SIS login flow

The below diagram illustrates the high-level login flow when using the `ic_sis_provider` canister.

1. An ICP application requests a SIS message from the `ic_sis_provider` canister on behalf of the user.

2. The application displays the SIS message to the user who signs it with their Sui wallet.

3. The application sends the signed SIS message to the `ic_sis_provider` canister to login the user. The canister verifies the signature and creates an identity for the user.

4. The application retrieves the identity from the `ic_sis_provider` canister.

5. The application can now use the identity to make authenticated calls to canisters.

![Sign in with Sui - Login flow](/media/flow.png)

## Resources

`ic-sis` consists of two main packages: the Rust support library and the prebuilt identity provider canister. The project also includes demo applications and a JS/TS/React support library for easy frontend integration.

### [ic_sis](https://github.com/Talentum-id/ic_sis/tree/main/packages/ic_sis)

Rust library that provides the necessary tools for integrating Sign-In with Sui (SIS) into ICP canisters, allowing users to sign in using their Sui wallets.

### [ic-sis-provider](https://github.com/Talentum-id/ic_sis/tree/main/packages/ic_sis_provider)

Prebuilt canister serving as a SIS identity provider for Internet Computer canisters. `ic_sis_provider` packages the [ic_sis](https://github.com/Talentum-id/ic_sis/tree/main/packages/ic_sis) library and makes it available as a canister that can easily be integrated into any Internet Computer application, independent of the application's programming language.

## Installation

### Using the Prebuilt Canister

Add the `ic_sis_provider` canister to your `dfx.json`:

```json
{
  "canisters": {
    "ic_sis_provider": {
      "type": "custom",
      "candid": "https://github.com/Talentum-id/ic_sis/releases/latest/download/ic_sis_provider.did",
      "wasm": "https://github.com/Talentum-id/ic_sis/releases/latest/download/ic_sis_provider.wasm.gz",
      "init_args": "(record { domain = \"yourdomain.com\"; uri = \"https://yourdomain.com\"; salt = \"your-secure-salt\"; network = opt \"mainnet\"; targets = null; sign_in_expires_in = null; session_expires_in = null; runtime_features = null })"
    }
  }
}