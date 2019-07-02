# Changes in Dcrypt

## 11.0.1
- Adds PHP 7.3 testing support to circle ci
- Clearer base64 class overload example
- Signature change on the Openssl::newKey method

## 11.0.0
- Move to default of SHA3-256 instead of SHA-256 for block ciphers
- Move to default of SHA3-512 instead of SHA-512 for OTP
- Fix error in Aes256Cbc cipher identifier
- Add tests for naming errors
- Remove all support for passwords in favor of strong keys
- All `$cost` related parameters removed
- Add namespaces to testing classes to prevent collisions (unlikely)
- Remove RC4 and Spritz support, will move to separate repo
- Made tests prettier
- Made vector generator more useful
- Removes some custom error handling by falling back on `strict_types=1`
- Removed unused exception types

## 10.0.1
- Add error handling when using cost with key
- Fixes to test readability
- Improvements to code comments

## 10.0.0
- More robust OO key management system for block ciphers and otp
- Moved to PHP minimum of 7.1
- More robust testing
- Stacking system to chain algorithms and ciphers
- Use `hash_hkdf()` to derive keys
- Drop support for some pointless code
- Move to circle-ci testing away from travis
- Removed ROT218

## 9.2.0
- Added ROT128 function class
- Added `examples/` folder
- Added type strictness to tests
- Revamped some docs

## 9.1.1
- Uses `strict_types=1` on all sources files (thank you PHP7)
- More functions are private/protected to keep API slim and consumable
- Isolated functions making dcrypt less likely to be misused
- Updates to code consistency

## 9.1.0
- Adds support for GCM encryption modes in PHP 7.1+
- Adds static encryption class for custom calls
- Improvements to structure
- Improvements to testing

## 9.0.0
- Removes some remains of mcrypt code

## 8.3.1
- Documentation updates
- Change to keying system
- Rename Aes wrapper class

## 8.3.0
- Rebuilt openssl encryption internal functions to be more easily extendable
- Simplified api
- Improved docs
- More sensible class names
- Removed gitignore
- Removed last composer dependency
- Smarter key generation step

## 8.2.1
- Minor scoping fixes