# Changelog

All notable changes to the `ic_sis` library will be documented in this file.

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