# OneTimePad

A novel counter-based stream cipher.

# Definitions

- `DATA` data to encrypt or decrypt
- `KEY` to be given to key manager
- `ALGO` default sha3-512
- `COUNTER`
- `HKDF`
  - algo
  - key
  - iv
  - info
- `IV` __a blank string__
- `INFO` is the concatenation of `LENGTH` and index number of `CHUNK`

# Method of Encrypt and Decryption
1. Break `DATA` into an array (`CHUNKS`) of strings with a max width equal to the size of the hashing algo
1. Compute `LENGTH` where `LENGTH = strlen(DATA)`
1. For each `CHUNK` in `CHUNKS`, replace with `CHUNK = CHUNK ^ HKDF(ALGO, KEY, IV, INFO)`
1. Once all elements in `CHUNKS` have been processed then `implode` and `return`