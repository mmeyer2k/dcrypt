# Changelog for `dcrypt`

## 13.2.2 [pending]
- Consolidate exceptions in openssl_*, hash_*, and random_* across PHP versions (should not break anything)
- Improve testing functionality and readability
- Confirm PHP 8.2 compatibility

## 13.2.1
- Remove file and class level phpdoc blocks
- Fix hash_hkdf error condition handling
- Remove duplicate key checks

## 13.2.0
- Adds the Str::token function

## 13.1.2
- Offload some functionality into OpensslKey object for readability
- OpensslKey throws exception if non-allowed properties are accessed
- Add ext-openssl and ext-mbstring to the requirements (makes IDE happy)
- Remove examples directory in favor of a more robust `docs/` option
- Improved exception handling that sheds some legacy crust
- Removed superfluous root namespace backslashes throughout project
- Modified ciphertext unpacking algorithm
- More complete docblocks

## 13.1.1
- Add test class for `Aes` static helper object
- Add base64 decode failure exception message for clarity

## 13.1.0
- Only require 32 byte keys from now on
- Remove key randomness testing in favor of trusting devs
- Add `Aes` as shorthand alias for `Aes256Gcm` to prevent typos

## 13.0.0
- Skip validating key when decrypting
- Clean up internal API
- Increase default AAD tag size

## 12.0.2
- More clarity and unity in internal API
- Add codesniffer to circle ci testing
- Lots of cs fixes

## 12.0.1
- Much more efficient testing config
- Fix spelling mistakes
- Create a keys guide
- Add vendor caching to circle tests
- Add a ONETIMEPAD spec document

## 12.0.0
- Increase minimum key size to 2048 bytes
- Adds PHP 7.3 testing support to circle ci
- Clearer base64 class overload example
- Signature change on the Openssl::newKey method
- Rename `Otp` to `OneTimePad`
- Refactor key object constructor

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

## 8.2.0
- Allow override of AES constants

## 8.1.0
- Isolated handling of openssl functions
- Cleaner calls to centralized hmac function
- Better internal API
- Dropped more PHP5 specific code
- Better code docs

## 8.0.1
- Released 8.0.1 before merging PR

## 8.0.0
- `Aes` has been renamed to `AesCbc`.
- Many improvents to structure and readability
- Added normalized hmac wrapper
