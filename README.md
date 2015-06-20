dcrypt
======
[![Build Status](https://travis-ci.org/mmeyer2k/dcrypt.png)](https://travis-ci.org/mmeyer2k/dcrypt)
[![Code Coverage](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/?branch=master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/?branch=master)
[![Code Climate GPA](https://codeclimate.com/github/mmeyer2k/dcrypt/badges/gpa.svg)](https://codeclimate.com/github/mmeyer2k/dcrypt)
[![License](https://poser.pugx.org/mmeyer2k/dcrypt/license.svg)](https://packagist.org/packages/mmeyer2k/dcrypt)
[![experimental](http://badges.github.io/stability-badges/dist/experimental.svg)](http://github.com/badges/stability-badges)

A library of essential encryption functions for PHP (5.3+).

# Installation
Add the following to the require section of your composer.json file, then run `composer install`.
```
"mmeyer2k/dcrypt": "dev-master"
```
Or using the command line...
```
composer global require mmeyer2k/dcrypt:dev-master
```
In environments where composer is not available, dcrypt can be used by including `load.php`.
# Features
## AES Encryption (via OpenSSL)
Quickly access symmetric encryption functions with `\Dcrypt\Aes`. When in doubt, use this class! All of the most secure options are the default. Naturally, strongly random initialization vectors are generated upon encryption and standard HMAC (sha256) checksums are verified (in a time-safe manner) before decryption.
```php
$encrypted = \Dcrypt\Aes::encrypt($plaintext, $password);

$plaintext = \Dcrypt\Aes::decrypt($encrypted, $password);
```

## Customizeable Encryption (via Mcrypt)
If you have special requirements, `\Dcrypt\Mcrypt` might be the best solution.
```php
# encrypt with serpent in ecb mode with sha512 hmac, for instance...
# the third parameter of 0 specifies that no extra key hardening will take place (see below...)
$encrypted = \Dcrypt\Mcrypt::encrypt('message', 'password', 0, MCRYPT_SERPENT, MCRYPT_MODE_ECB, 'sha512');
```
As with `\Dcrypt\Aes`, all time-safe HMAC verification, strong IV creation and padding (PKCS#7) are handled for you.

When used with all default options, `\Dcrypt\Mcrypt` is compatible with `\Dcrypt\Aes`.
```php
$encrypted = \Dcrypt\Mcrypt::encrypt($plaintext, 'password');

$plaintext = \Dcrypt\Aes::decrypt($encrypted, 'password');
```

Supported (and tested) modes: `MCRYPT_MODE_CBC`, `MCRYPT_MODE_CFB`, `MCRYPT_MODE_ECB`, `MCRYPT_MODE_OFB`, `MCRYPT_MODE_NOFB`

Supported (and tested) ciphers: `MCRYPT_3DES`, `MCRYPT_BLOWFISH`, `MCRYPT_BLOWFISH_COMPAT`, `MCRYPT_DES`, `MCRYPT_LOKI97`, `MCRYPT_CAST_128`, `MCRYPT_CAST_256`, `MCRYPT_RC2`, `MCRYPT_RIJNDAEL_128`, `MCRYPT_RIJNDAEL_192`, `MCRYPT_RIJNDAEL_256`, `MCRYPT_SAFERPLU`, `MCRYPT_SERPENT`, `MCRYPT_TRIPLEDES`, `MCRYPT_TWOFISH`, `MCRYPT_XTEA`

Supported (and tested) hash algos: all!

**NOTE**: PHP's libmcrypt has fallen out of favor due to its stale codebase and inability to use AES-NI. Only use these features if there is a strong need. In nearly all cases `\Dcrypt\Aes` (which uses OpenSSL) is preferred.

## Iterative HMAC Key Hardening
To reduce the effectiveness of brute-force cracking on your encrypted blobs, you can provide an integer `$cost` parameter
in your encryption/decryption calls. This integer will cause dcrypt to perform `$cost` number of extra HMAC operations on the key before passing it off to the underlying encryption system.

All keys are hashed at least once with the initialization vector as an extra layer of protection.

```php
$encrypted = \Dcrypt\Aes::encrypt($plaintext, $password, 10000);

$plaintext = \Dcrypt\Aes::decrypt($encrypted, $password, 10000);
```
`$cost` can also be passed into the third parameter of `\Dcrypt\Mcrypt`'s functions.

## Fast One Time Pad Encryption
Extremely fast symmetric stream encryption is available with the `\Dcrypt\Otp` class.
```php
$encrypted = \Dcrypt\Otp::crypt($plaintext, $password);

$plaintext = \Dcrypt\Otp::crypt($encrypted, $password);
```

## PKCS #7 Padding
PKCS#7 style padding is available via the `Pkcs7::pad()` and `Pkcs7::unpad()` functions.
```php
\Dcrpyt\Pkcs7::pad('aaaabbbb', 3); # = aaaabbbb\x01

\Dcrpyt\Pkcs7::pad('aaaabbbb', 4); # = aaaabbbb\x04040404
```

```php
\Dcrpyt\Pkcs7::unpad("aaaabbbb\x01"); # = aaaabbbb

\Dcrpyt\Pkcs7::unpad("aaaabbbb\x04\x04\x04\x04"); # = aaaabbbb
```

## Strong Authenticated Key Derivation Function
`Dcrypt\Hash` is an opaque 512 bit iterative hash function. It accepts cost values between 1 and 255.
```php
$hash = \Dcrypt\Hash::make($plaintext, $password, $cost);

$bool = \Dcrypt\Hash::verify($plaintext, $hash, $password);
```
## Secure Random Number Generation
When you absolutely MUST have cryptographically secure random numbers `\Dcrypt\Random` will give them to you or throw an exception.
```php
# get 8 random bytes
$iv = \Dcrypt\Random::get(8);
```

## Time-safe String Comparison
Dcrypt uses time-safe string comparisons in all sensitive areas. The same function that is used internally is also exposed for use in your projects.
```php
$equals = \Dcrypt\Str::equal('known', 'given');
```

## For Fun
`\Dcrypt\Rc4` and `\Dcrypt\Spritz` are pure PHP implementations of the immortal RC4 cipher and its successor Spritz.
```php
$encrypted = \Dcrypt\Rc4::crypt($plaintext, $password);

$plaintext = \Dcrypt\Rc4::crypt($encrypted, $password);
```
```php
$encrypted = \Dcrypt\Spritz::crypt($plaintext, $password);

$plaintext = \Dcrypt\Spritz::crypt($encrypted, $password);
```

# Usage Notes
1. All encryption functions and `\Dcrypt\Hash::make()` output raw binary data.
1. All encryption functions and `\Dcrypt\Hash::make()` accept any binary data of arbitrary length as `$password`.
  1. Dcrypt takes special steps to avoid frivolus concatenations of potentially large input parameters.
  1. `$password` type parameters are freqently concatentated. Therefore, avoid using excessively large passwords when memory is an issue. 
1. Dcrypt is safe to use on systems that have `mbstring.func_overload` enabled.
