# Crypto Specification

This document serves as a high level design document for the Openssl based encryption functions of dcrypt.

# Definitions
- `SALT` initialization vector generated with `random_bytes`.
- `COST` integer which will ultimately be passed as cost parameter to `PBKDF2`.
- `CIPHER` the chosen cipher method as a string
- `ALGO` the chosen hmac algorithm as a string
- `PBKDF2` is the password-based key derivation function provided by PHP (hash_pbkdf2). The parameters are:
    - `ALGO`
    - `PASSWORD` + `CIPHER`
    - `SALT`
    - `COST`
- `HKDF` is the password-based key derivation function provided by PHP (hash_hkdf). The parameters are:
    - 
- `ENCRINFO` is the string `encryptionKey`
- `AUTHINFO` is the string `authenticationKey`
- `M` the message to be encrypted

# Steps for encryption
1. Obtain a new IV of appropriate size for given `CIPHER`
1. Derive a new key `PKEY` from `PASSWORD` using `PBKDF2()`
1. Derive authentication key `AKEY` = `HKDF` with info parameter = `AUTHINFO`
1. Derive encryption key `EKEY` = `HKDF` with info parameter = `ENCRINFO`
1. Use `OPENSSL` to get the raw encrypted string using all 