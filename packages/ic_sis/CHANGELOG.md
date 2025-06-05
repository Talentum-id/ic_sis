# Changelog

All notable changes to the `ic_sis` library will be documented in this file.

## 0.2.0 (2025-06-05)

### 🚀 Major Features Added
- **BCS Serialization**: Implemented proper Binary Canonical Serialization (BCS) for SUI compatibility
- **Intent Signing Protocol**: Full compliance with SUI's intent signing standard
- **Enhanced Signature Verification**: Complete support for all major SUI signature schemes

### ✨ New Features
- Added `BcsSisMessage` struct for canonical serialization
- Implemented `create_auth_intent_hash()` for authentication messages
- Added proper intent scope separation (authentication vs transaction)
- Enhanced ECDSA signature validation with canonical form checking
- Added `validate_bcs_serialization()` method for debugging
- Implemented `compare_serializations()` for BCS vs JSON analysis

### 🔧 Improvements
- **Intent Prefixes**: Now uses `[3, 0, 0]` for authentication vs `[0, 0, 0]` for transactions
- **Signature Verification**: Fixed hash flow to prevent double hashing
- **ECDSA Internal Hashing**: Added SHA-256 hashing of Blake2b digest for ECDSA schemes
- **Canonical Signatures**: Validates s-value is in lower half of curve order (BIP-0062)
- **Error Handling**: Enhanced error messages and validation
- **Test Coverage**: Comprehensive BCS serialization and intent signing tests

### 🔐 Security Enhancements
- Proper Blake2b hashing with correct intent prefixes
- ECDSA signature canonicality validation
- Enhanced public key format validation
- Improved address derivation verification

### 🛠️ Technical Changes
- `to_sign_bytes()` now uses BCS serialization by default
- Added `to_json_bytes()` for backward compatibility
- Modified signature verification flow for proper SUI compliance
- Enhanced field ordering in BCS serialization for deterministic output

### 📦 Dependencies
- Added `bcs = "0.1.4"` for Binary Canonical Serialization

### 🧪 Testing
- Added comprehensive BCS serialization tests
- Enhanced intent message creation tests
- Added deterministic serialization validation
- Improved signature verification test coverage

### 💥 Breaking Changes
- `verify_sui_signature()` now expects Blake2b hash instead of raw message
- `create_intent_message()` now returns 32-byte hash directly
- Modified internal signature verification flow

### 📚 Documentation
- Updated README with BCS serialization information
- Enhanced code documentation for intent signing
- Added comprehensive examples for signature verification

## 0.1.3 (2025-06-04)

### Changed
- Fix `sis_login` with signature of ZKlogin

## 0.1.2 (2025-05-16)

### Changed
- Added `bytes_to_sui_address` to src/sui.rs

## 0.1.1 (2025-05-13)

### Changed
- Updated `verify_sui_signature` to return the derived address instead of a boolean
- Enhanced login function to verify derived address matches provided address
- Added `prune_all` and related functions for better state management

## 0.1.0 (2025-03-17)

Initial release of the ic_sis library.

### Added
- Core functionality for Sign-In with Sui (SIS) authentication
- Integration with the Internet Computer architecture
- Sui message and signature handling
- Session management and delegation
- Login flow implementation
- Configuration settings for different Sui networks