# Changelog

## 0.2.1 (2025-06-19)

### 🔧 Improvements
- **Fixed sis_prepare_login**: Updated sis_message to be hex encoded

## 0.2.0 (2025-06-05)

### 🚀 Major Features Added
- **ic_sis v0.2.0 Integration**: Updated to use the latest ic_sis library with BCS serialization
- **Enhanced Message Format**: Now returns human-readable SIS messages for better frontend integration
- **Improved Signature Verification**: Updated to use new intent signing protocol from ic_sis v0.2.0

### ✨ New Features
- BCS serialization support through ic_sis v0.2.0
- Enhanced error handling with more descriptive messages
- Improved test coverage for new message formats

### 🔧 Improvements
- **Message Display**: `sis_prepare_login` now returns human-readable message format
- **Better Validation**: Enhanced address and signature validation
- **Test Updates**: All tests updated for v0.2.0 compatibility
- **MSRV**: Updated to Rust 1.73 for compatibility

### 💥 Breaking Changes
- SIS message format changed from JSON to human-readable format
- Updated ic_sis dependency to v0.2.0 with breaking API changes
- Modified signature verification flow

### 📦 Dependencies
- Updated `ic_sis` to version `0.2.0`
- Updated `rust-version` to `1.73`

### 🧪 Testing
- Updated integration tests for new message format
- Enhanced test cases for BCS serialization
- Improved error message validation in tests

## 0.1.1 (2025-06-14)

Updated ic-sis library version

## 0.1.0 (2025-05-16)

Initial release of the ic_sis_provider canister.

### Added
- Sui wallet authentication for Internet Computer applications
- Principal generation from Sui addresses
- Delegation management for authenticated users
- Address and principal mapping
- Support for Ed25519, Secp256k1, and Secp256r1 signature schemes