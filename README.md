dcrypt
======
[![Build Status](https://travis-ci.org/mmeyer2k/dcrypt.png)](https://travis-ci.org/mmeyer2k/dcrypt)
[![Code Coverage](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/?branch=master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/?branch=master)
[![Code Climate GPA](https://codeclimate.com/github/mmeyer2k/dcrypt/badges/gpa.svg)](https://codeclimate.com/github/mmeyer2k/dcrypt)
[![License](https://poser.pugx.org/mmeyer2k/dcrypt/license.svg)](https://packagist.org/packages/mmeyer2k/dcrypt)
[![experimental](http://badges.github.io/stability-badges/dist/experimental.svg)](http://github.com/badges/stability-badges)

A library of essential encryption functions. 

# Installation
Add the following to the require-dev section of your composer.json file.
```
"mmeyer2k/dcrypt": "dev-master"
```
After modification of the composer.json file, run ...
```
composer install
```
In environments where composer is not available, dcrypt can be used by including `load.php`.
# Features
## AES (via OpenSSL)
Quickly access symmetric encryption functions with \Dcrypt\Aes. When in doubt, use this class! All of the most secure options are the default.
```php
$encrypted = Dcrypt\Aes::encrypt($message, $password);

$decrypted = Dcrypt\Aes::decrypt($encrypted, $password);
```
## Customizeable Encryption (via Mcrypt)
If you have special requirements, \Dcrypt\Mcrypt might be the best solution.
```
# encrypt with serpent in ecb mode with sha512 hmac, for instance...
$encrypted = \Dcrypt\Mcrypt::encrypt('message', 'password', MCRYPT_MODE_ECB, MCRYPT_SERPENT, 'sha256');
```
Supported (and tested) modes: `MCRYPT_MODE_CBC`, `MCRYPT_MODE_CFB`, `MCRYPT_MODE_ECB`, `MCRYPT_MODE_OFB`, `MCRYPT_MODE_NOFB`

Supported (and tested) ciphers: `MCRYPT_3DES`, `MCRYPT_BLOWFISH`, `MCRYPT_BLOWFISH_COMPAT`, `MCRYPT_DES`, `MCRYPT_LOKI97`, `MCRYPT_CAST_128`, `MCRYPT_CAST_256`, `MCRYPT_RC2`, `MCRYPT_RIJNDAEL_128`, `MCRYPT_RIJNDAEL_192`, `MCRYPT_RIJNDAEL_256`, `MCRYPT_SAFERPLU`, `MCRYPT_SERPENT`, `MCRYPT_TRIPLEDES`, `MCRYPT_TWOFISH`, `MCRYPT_XTEA`

Supported (and tested) hash algos: all!

NOTE: PHP Mcrypt has fallen out of favor due to its stale codebase and inability to use AES-NI. Only use these features if there is a strong need. In nearly all cases \Dcrypt\Aes (which uses OpenSSL) is preferred.

## Fast One Time Pad Encryption
Extremely fast symmetric stream encryption is available with the `Otp` class.
```php
$crypted = \Dcrypt\Otp::crypt('plaintext', 'key');

# outputs 'plaintext'
echo \Dcrypt\Otp::crypt($crypted, 'key'); 
```
## PKCS #7 Padding
PKCS#7 style padding is available via the `Pkcs7::pad()` and `Pkcs7::unpad()` functions.
## Strong Authenticated Key Derivation Function
```php
$hash = Dcrypt\Hash::make('plaintext', 'key');

# to verify hashes, use Hash::verify()
$verified = Dcrypt\Hash::verify('plaintext', $hash, 'key');
```
## Secure Random Number Generation
When you absolutely MUST have cryptographically secure random numbers \Dcrypt\Random will give them to you or throw an exception.
```
# get 8 random bytes
$iv = \Dcrypt\Random::get(8);
```
