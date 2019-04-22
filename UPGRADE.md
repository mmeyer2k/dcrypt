# Upgrade from 8.x to 9.x
Version 9 is a MAJOR update to dcrypt.
It removes all legacy crutches and moves to use more a more modern design.

- All data encrypted with AesCtr and AesCbc prior to 9.0 will not be decryptable in 9.0.
- OpenSSL based decryption wrapper functions no longer need to pass the `$cost` parameter.


# Upgrade from 7.x to 8.x

# Upgrade from 6.x to 7.x
