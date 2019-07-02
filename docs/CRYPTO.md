# Crypto Specification

This document serves as a high level design document for the block cipher functions of dcrypt.

## Definitions
- `SALT` initialization vector generated with `random_bytes`.
- `CIPHER` the chosen cipher method as a string
- `ALGO` the chosen hmac algorithm as a string
- `KEY` high entropy key selected for symmetric encryption
- `ENCRINFO` is the string `encryptionKey` + `|` + `CIPHER`
- `AUTHINFO` is the string `authenticationKey` + `|` + `CIPHER`
- `MTEXT` the plaintext message to be encrypted
- `HKDF` is the key derivation function supported by PHP ([hash_hkdf](https://www.php.net/manual/en/function.hash-hkdf.php)) and defined as ([RFC-5869](https://tools.ietf.org/html/rfc5869)). The parameters are:
    - hashing algo to use
    - key to hash with
    - info string parameter
- `HMAC` is a HMAC checksum function supported by PHP (hash_hmac). The parameters are:
    - input data to hash
    - hashing algo to use
    - key to hash with
- `OPENSSL_ENCRYPT`. The parameters are:
    - input data to encrypt
    - key to hash with
    - iv
- `OPENSSL_DECRYPT`. The parameters are:
    - input data to decrypt
    - key to hash with
    - iv
    - tag

## Testing key validity
Before any encryption/decryption calls, a key derivation object must be created.
This object tests the key supplied to it to make sure that it:
1. Can be decoded as a base64 string
1. The size after decoding meets or exceeds 2048 bytes
1. Contains a minimum amount of entropy as determined by counting the unique characters in the key

Providing a high quality key is __essential__ to the security level it provides.

## Steps for encryption
1. Obtain a new `SALT` of appropriate size for given `CIPHER`
1. Derive authentication key `AKEY = HKDF(ALGO, KEY, AUTHINFO)`
1. Derive encryption key `EKEY = HKDF(ALGO, KEY, ENCRINFO)`
1. Encrypt the data as `CTEXT = OPENSSL_ENCRYPT(MTEXT, EKEY, SALT)`
1. Generate a checksum where `CHECKSUM = HMAC(CTEXT, ALGO, AKEY)`
1. Concatenate and return the following values
    1. `SALT`
    1. `CHECKSUM`
    1. `TAG` (if required by `CIPHER`, otherwise skip)
    1. `CTEXT`
    
## Steps for decryption
1. Pop `SALT` off front of `CTEXT`
1. Same as step 2 from above
1. Same as step 3 from above
1. Pop `CHECKSUM` from front of `CTEXT`
1. Pop `TAG` from front of `CTEXT`
1. Generate a checksum where `COMPUTED = HMAC(CTEXT, ALGO, AKEY)`
1. If `COMPUTED != CHECKSUM` throw an exception
1. Decrypt data as `MTEXT = OPENSSL_DECRYPT(CTEXT, EKEY, SALT, TAG)`
1. Return `MTEXT`