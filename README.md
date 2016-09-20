:closed_lock_with_key:dcrypt
======
[![Build Status](https://travis-ci.org/mmeyer2k/dcrypt.png)](https://travis-ci.org/mmeyer2k/dcrypt)
[![Code Coverage](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/?branch=master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/?branch=master)
[![Code Climate GPA](https://codeclimate.com/github/mmeyer2k/dcrypt/badges/gpa.svg)](https://codeclimate.com/github/mmeyer2k/dcrypt)
[![License](https://poser.pugx.org/mmeyer2k/dcrypt/license.svg)](https://packagist.org/packages/mmeyer2k/dcrypt)
[![Latest Stable Version](https://poser.pugx.org/mmeyer2k/dcrypt/version)](https://packagist.org/packages/mmeyer2k/dcrypt)
[![SensioLabsInsight](https://insight.sensiolabs.com/projects/c48adefc-874e-4d14-88dc-05f7f407f968/mini.png)](https://insight.sensiolabs.com/projects/c48adefc-874e-4d14-88dc-05f7f407f968)

A petite library of essential encryption functions for PHP (5.3 - 7.0).

- [Install](#install)
- [Features](#features)
  - [Block Ciphers](#block-ciphers)
  - [Stream Ciphers](#stream-ciphers)
  - [PKCS #7 Padding](#pkcs-7-padding)
  - [Key Derivation Function](#key-derivation-function)
  - [Time-safe String Comparison](#time-safe-string-comparison)
  - [Secure Random Byte Generator](#secure-random-byte-generator)
- [Usage Notes](#usage-notes)
- [API Documentation](#api-documentation)

# Install
Add the following to the require section of your `composer.json` file, then run `composer install`.
```json
"require": {
  "mmeyer2k/dcrypt": "~3.0"
}
```
Or using the command line...
```bash
composer require "mmeyer2k/dcrypt=~3.0"
```
In environments where composer is not available, Dcrypt can be used by including `load.php`.
```php
require 'path/to/dcrypt/load.php';
```
# Features

## Block Ciphers

### AES-256-CBC Encryption (via OpenSSL)
Quickly access AES-256-CBC encryption with `\Dcrypt\Aes`. **When in doubt, use this class!** All of the most secure options are the default. Naturally, strongly random initialization vectors are generated upon encryption and standard HMAC (SHA-256) checksums are verified in a time-safe manner before decryption.
```php
$encrypted = \Dcrypt\Aes::encrypt($plaintext, $password);

$plaintext = \Dcrypt\Aes::decrypt($encrypted, $password);
```

### AES-256-CTR Encryption (via OpenSSL)
If the `CTR` mode is preferred, `\Dcrypt\AesCtr` can be used.
```php
$encrypted = \Dcrypt\AesCtr::encrypt($plaintext, $password);

$plaintext = \Dcrypt\AesCtr::decrypt($encrypted, $password);
```


### Customizable Encryption (via Mcrypt)
If you have special requirements, `\Dcrypt\Mcrypt` might be the best solution.
```php
# encrypt with serpent in ecb mode with sha512 hmac
$encrypted = \Dcrypt\Mcrypt::encrypt(
  'message', 
  'password', 
  0, # specifies that no key hardening will take place (see below...)
  MCRYPT_SERPENT, 
  MCRYPT_MODE_ECB, 
  'sha512'
);
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

**NOTE**: PHP's libmcrypt has fallen out of favor due to its stale codebase and inability to use AES-NI. Only use `\Dcrypt\Mcrypt` if there is a strong need. In nearly all cases `\Dcrypt\Aes` (which uses OpenSSL) is preferred.

### Iterative HMAC Key Hardening
To reduce the effectiveness of brute-force cracking on your encrypted blobs, you can provide an integer `$cost` parameter
in your encryption/decryption calls. This integer will cause dcrypt to perform `$cost` number of extra HMAC operations on the key before passing it off to the underlying encryption system.

All keys are hashed at least once with the initialization vector as an extra layer of protection.

```php
$encrypted = \Dcrypt\Aes::encrypt($plaintext, $password, 10000);

$plaintext = \Dcrypt\Aes::decrypt($encrypted, $password, 10000);
```
`$cost` can also be passed into the third parameter of `\Dcrypt\Mcrypt`'s functions.

### Tamper Protection
By default, `\Dcrypt\Aes`, `\Dcrypt\AesCtr` and `\Dcrypt\Mcrypt` will throw an `InvalidArgumentException` 
if *before* decryption if the supplied checksum is not valid.
```php
try {
  $decrypted = \Dcrypt\Aes::decrypt($badInput, $password);
} catch (\Exception $ex) {
  # do something
}
```

## Stream Ciphers

### One Time Pad Encryption
Fast symmetric stream encryption is available with the `\Dcrypt\Otp` class.
`\Dcrypt\Otp` uses SHA-512 (by default) to output a keystream that is ⊕'d with the input in 512 bit chunks. 
```php
$encrypted = \Dcrypt\Otp::crypt($plaintext, $password);

$plaintext = \Dcrypt\Otp::crypt($encrypted, $password);
```

`\Dcrypt\Otp` can also be configured to use any other hashing algorithm to generate the
pseudorandom keystream.
```php
$encrypted = \Dcrypt\Otp::crypt($plaintext, $password, 'whirlpool');

$plaintext = \Dcrypt\Otp::crypt($encrypted, $password, 'whirlpool');
```

### Rivest's Ciphers
`\Dcrypt\Rc4` and `\Dcrypt\Spritz` are pure PHP implementations of the immortal [RC4](https://en.wikipedia.org/wiki/RC4) cipher and its successor [Spritz](https://people.csail.mit.edu/rivest/pubs/RS14.pdf).
```php
$encrypted = \Dcrypt\Rc4::crypt($plaintext, $password);

$plaintext = \Dcrypt\Rc4::crypt($encrypted, $password);
```
```php
$encrypted = \Dcrypt\Spritz::crypt($plaintext, $password);

$plaintext = \Dcrypt\Spritz::crypt($encrypted, $password);
```

**NOTE**: These implementations are for reference only. The RC4 cipher in general has many known security problems, and the Spirtz implementation provided here has not been verified against known test vectors. 
Both are very slow and inefficient. This was just for fun. Use `Dcrypt\Aes` for anything important.

**NOTE**: Backwards compatibility breaking changes to these classes will not result in an incremented major version number.

## PKCS #7 Padding
PKCS#7 style padding is available via the `Pkcs7::pad()` and `Pkcs7::unpad()` functions.
```php
\Dcrpyt\Pkcs7::pad('aaaabbbb', 3); # = aaaabbbb\x01

\Dcrpyt\Pkcs7::pad('aaaabbbb', 4); # = aaaabbbb\x04\x04\x04\x04
```

```php
\Dcrpyt\Pkcs7::unpad("aaaabbbb\x01"); # = aaaabbbb

\Dcrpyt\Pkcs7::unpad("aaaabbbb\x04\x04\x04\x04"); # = aaaabbbb
```

## Key Derivation Function
`Dcrypt\Hash` is an opaque 512 bit iterative hash function. First, SHA-256 is 
used to hash a 16 byte initialization vector with your secret password to create
a unique key. Then `$cost` number of HMAC iterations are performed on the input
using the unique key.

The `$cost` parameter can be any integer between 0 and 2<sup>32</sup> - 1. This
`$cost` value is stored as 4 encrypted bytes in the output. A `$cost` value of 
`0` results in only a single hash being performed.

```php
$hash = \Dcrypt\Hash::make($plaintext, $password, $cost);

$bool = \Dcrypt\Hash::verify($plaintext, $hash, $password);
```


## Time-safe String Comparison
Dcrypt uses time-safe string comparisons in all sensitive areas. The same function that is used internally is also exposed for use in your projects.
```php
$equals = \Dcrypt\Str::equal('known', 'given');
```

## Secure Random Byte Generator
When you absolutely **must** have cryptographically secure random bytes `\Dcrypt\Random` will give them to you or throw an exception.
```php
$iv = \Dcrypt\Random::bytes(8); # get 8 random bytes
```

# Usage Notes
1. All encryption functions and `\Dcrypt\Hash::make()` output raw binary data.
1. All encryption functions and `\Dcrypt\Hash::make()` accept any binary data of arbitrary length as `$input` and `$password`.
  1. Dcrypt takes special steps to avoid frivolus concatenations of potentially large `$input` type parameters.
  1. `$password` type parameters are freqently concatentated. Therefore, avoid using excessively large passwords when memory is an issue. 
1. Dcrypt is safe to use on systems that have `mbstring.func_overload` enabled.
1. Dcrypt's block ciphers and `Hash::make()` output very space efficient blobs. Every bit is used to its fullest potential. 
  1. Known offset + length is how the components of the cyphertexts are parsed. No serialization, marker bytes, encoding schemes or any other nonsense is used. Because of this, the output size of the block ciphers is easily predictable.
  1. The output size of `Aes::encrypt` on a 10 byte plaintext would be: IV (16 bytes) + SHA-256 HMAC (32 bytes) + encrypted plaintext and padding bytes (16 bytes) = 64 bytes.
1. Dcrypt is built entirely with static functions. If you are using the `new` keyword on any Dcrypt classes, you are doing it wrong!

# API Documentation
The latest API documentation can be found [here](https://apigen.ci/github/mmeyer2k/dcrypt/namespace-Dcrypt.html).
