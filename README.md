:closed_lock_with_key:dcrypt
======
[![Total Downloads](https://poser.pugx.org/mmeyer2k/dcrypt/downloads)](https://packagist.org/packages/mmeyer2k/dcrypt)
[![Build Status](https://travis-ci.org/mmeyer2k/dcrypt.png)](https://travis-ci.org/mmeyer2k/dcrypt)
[![Code Coverage](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/?branch=master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/?branch=master)
[![Code Climate GPA](https://codeclimate.com/github/mmeyer2k/dcrypt/badges/gpa.svg)](https://codeclimate.com/github/mmeyer2k/dcrypt)
[![License](https://poser.pugx.org/mmeyer2k/dcrypt/license.svg)](https://packagist.org/packages/mmeyer2k/dcrypt)
[![Latest Stable Version](https://poser.pugx.org/mmeyer2k/dcrypt/version)](https://packagist.org/packages/mmeyer2k/dcrypt)
[![SensioLabsInsight](https://insight.sensiolabs.com/projects/c48adefc-874e-4d14-88dc-05f7f407f968/mini.png)](https://insight.sensiolabs.com/projects/c48adefc-874e-4d14-88dc-05f7f407f968)

A petite library of essential encryption functions for PHP7.
For PHP5 support, check out the legacy branch [here](https://github.com/mmeyer2k/dcrypt/tree/4.0.2).

- [Install](#install)
- [Features](#features)
  - [Block Ciphers](#block-ciphers)
  - [Stream Ciphers](#stream-ciphers)
  - [PKCS #7 Padding](#pkcs-7-padding)
  - [Key Derivation Function](#key-derivation-function)
  - [Time-safe String Comparison](#time-safe-string-comparison)
- [Usage Notes](#usage-notes)
- [Show me some love](#show-me-some-love-heart_eyes) :heart_eyes:

# Install
Add `dcrypt` to your composer.json file requirements.
Don't worry, `dcrypt` does not have any dependencies of its own.
```bash
composer require "mmeyer2k/dcrypt=~8.0"
```
In environments where composer is not available, Dcrypt can be used by including `load.php`.
```php
require 'path/to/dcrypt/load.php';
```
# Features

## Block Ciphers

### AES-256-CBC Encryption
Quickly access AES-256-CBC encryption with `\Dcrypt\AesCbc`.
All of the most secure options are the default. 
Naturally, strongly random initialization vectors are generated upon encryption and standard HMAC (SHA-256) checksums are verified in a time-safe manner before decryption.
```php
$encrypted = \Dcrypt\AesCbc::encrypt($plaintext, $password);

$plaintext = \Dcrypt\AesCbc::decrypt($encrypted, $password);
```

### AES-256-CTR Encryption
If the `CTR` mode is preferred, `\Dcrypt\AesCtr` can be used.
```php
$encrypted = \Dcrypt\AesCtr::encrypt($plaintext, $password);

$plaintext = \Dcrypt\AesCtr::decrypt($encrypted, $password);
```
[Definitive StackExchange thread on CBC vs CTR](https://security.stackexchange.com/questions/27776/block-chaining-modes-to-avoid/27780#27780)

### Custom Encryption Suites
`dcrypt`'s internal functions are easily extendable by overloading the `OpensslBridge` class. 
Use `openssl_get_cipher_method()` and `hash_algos()` to gather available options.

```php
<?php

/**
 * Use blowfish64 + crc32 to create smaller output sizes. 
 * This is useful for medium security situations where minimal space consumption is important.
 */
class TinyFish extends \Dcrypt\OpensslBridge 
{
    /**
     * Specify using blowfish ofb cipher method
     *
     * @var string
     */
    const CIPHER = 'bf-ofb';
    
    /**
     * Use crc32 hashing algo to authenticate messages
     *
     * @var string
     */
    const CHKSUM = 'crc32';
}
```

**NOTE**:
Only `\Dcrypt\AesCbc` and `\Dcrypt\AesCtr` are tested by this library. If you roll your own, write some tests!

### Iterative HMAC Key Hardening
To reduce the effectiveness of brute-force cracking on your encrypted blobs, you can provide an integer `$cost` parameter in your encryption/decryption calls. 
This integer will cause dcrypt to perform `$cost` number of extra HMAC operations on the key before passing it off to the underlying encryption system.
```php
$encrypted = \Dcrypt\AesCbc::encrypt($plaintext, $password, 10000);

$plaintext = \Dcrypt\AesCbc::decrypt($encrypted, $password, 10000);
```

### Tamper Protection
By default, `AesCbc` and `AesCtr` will throw an `InvalidArgumentException` 
*before* decryption if the supplied checksum is not valid.
```php
try {
    $decrypted = \Dcrypt\AesCtr::decrypt($badInput, $password);
} catch (\InvalidArgumentException $ex) {
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

**NOTE**: 
These implementations are for reference only. 
The RC4 cipher in general has many known security problems, and the Spirtz implementation provided here has not been verified against known test vectors. 
Both are very slow and inefficient. 
This was just for fun. 
Use block ciphers for anything important.

**NOTE**: 
Backwards compatibility breaking changes to these classes will not result in an incremented major version number.

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
`Dcrypt\Hash` is an opaque 512 bit iterative hash function. 
First, SHA-256 is used to hash a 16 byte initialization vector with your secret password to create a unique key.
Then `$cost` number of HMAC iterations are performed on the input using the unique key.

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

# Usage Notes
1. All functions input/output raw binary strings.
1. All functions accept any string of arbitrary length for `$input` and `$password` type parameters.
  1. Dcrypt takes special steps to avoid frivolus concatenations of potentially large `$input` type parameters.
  1. `$password` type parameters are freqently concatentated. Therefore, avoid using excessively large passwords when memory is an issue.
1. Dcrypt's block ciphers and `Hash::make()` output very space efficient blobs. Every bit is used to its fullest potential. 
  1. Known offset + length is how the components of the cyphertexts are parsed. No serialization, marker bytes, encoding schemes or any other nonsense is used. Because of this, the output size of the block ciphers is easily predictable and is as compact as possible.
  1. The output size of `AesCbc::encrypt` on a 10 byte plaintext would be: IV (16 bytes) + SHA-256 HMAC (32 bytes) + encrypted plaintext and padding bytes (16 bytes) = 64 bytes.
1. Dcrypt is built entirely with static functions. If you are using the `new` keyword on any Dcrypt classes, you are doing it wrong!

# Show me some love :heart_eyes:
Developing dcrypt has been a labor of love for many years. 
If you find dcrypt useful, please consider donating some Litecoin to `LN97LrLCNiv14V6fntp247H2pj9UiFzUQZ`.
 
 ![litecoin address](https://rawgit.com/mmeyer2k/dcrypt/master/litecoin.png)

 [Other cryptos are cool too...](https://freewallet.org/id/1f01979d/ltc/).
