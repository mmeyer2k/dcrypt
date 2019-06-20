:closed_lock_with_key:dcrypt
======
[![Total Downloads](https://poser.pugx.org/mmeyer2k/dcrypt/downloads)](https://packagist.org/packages/mmeyer2k/dcrypt)
[![Build Status](https://circleci.com/gh/mmeyer2k/dcrypt/tree/master.svg?style=shield)](https://travis-ci.org/mmeyer2k/dcrypt)
[![Code Coverage](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/?branch=master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/?branch=master)
[![Code Climate GPA](https://codeclimate.com/github/mmeyer2k/dcrypt/badges/gpa.svg)](https://codeclimate.com/github/mmeyer2k/dcrypt)
[![License](https://poser.pugx.org/mmeyer2k/dcrypt/license.svg)](https://packagist.org/packages/mmeyer2k/dcrypt)
[![Latest Stable Version](https://poser.pugx.org/mmeyer2k/dcrypt/version)](https://packagist.org/packages/mmeyer2k/dcrypt)

A petite library of essential encryption functions for PHP 7.1+.
For legacy PHP version support, look [here](https://github.com/mmeyer2k/dcrypt/blob/master/docs/LEGACY.md).

- [Install](#install)
- [Features](#features)
  - [Block Ciphers](#block-ciphers)
  - [Stream Ciphers](#stream-ciphers)
  - [PKCS #7 Padding](#pkcs-7-padding)
  - [Key Derivation Function](#key-derivation-function)
  - [Time-safe String Comparison](#time-safe-string-comparison)
- [Show me some love](#show-me-some-love-heart_eyes) :heart_eyes:

# Install
Add dcrypt to your composer.json file requirements.
Don't worry, dcrypt does not have any dependencies of its own.
```bash
composer require "mmeyer2k/dcrypt=^10.0"
```

# Features
## Block Ciphers
Dcrypt helps application developers avoid common mistakes in crypto implementations that leave data at risk.
The primary features of dcrypt's block cipher engine are:
- Elegent API helps keep your code readable, auditable and understandable
- Allows custom combinations of encryption and hashing algorithms to fit different purposes
- Ciphertext, authentication tag (if present), IV and HMAC are all packed into a single string for simplicity
- Strongly random initialization vectors are generated with `random_bytes()`
- SHA256 (default) HMAC checksums are verified before decryption using a time-safe equivalence function

### AES-256-GCM Encryption
PHP 7.1 comes with support for new AEAD encryption modes, GCM being considered the best of these.
Small authentication tags are selected because dcrypt already provides SHA-256 HMAC based authentication.
Using this mode essentially adds an extra 32 bit checksum to the ciphertext.

```php
$encrypted = \Dcrypt\AesGcm::encrypt($plaintext, $password);

$plaintext = \Dcrypt\AesGcm::decrypt($encrypted, $password);
```

### AES-256-CBC Encryption
CBC mode is better for some usages since it uses padding and therefore leaks less information about plaintext length.

```php
$encrypted = \Dcrypt\AesCbc::encrypt($plaintext, $password);

$plaintext = \Dcrypt\AesCbc::decrypt($encrypted, $password);
```

### AES-256-CTR Encryption
If the CTR mode is preferred, `\Dcrypt\AesCtr` can be used.

```php
$encrypted = \Dcrypt\AesCtr::encrypt($plaintext, $password);

$plaintext = \Dcrypt\AesCtr::decrypt($encrypted, $password);
```
[Definitive StackExchange thread on CBC vs CTR](https://security.stackexchange.com/questions/27776/block-chaining-modes-to-avoid/27780#27780)

### AES-256-OFB Encryption
OFB mode is supported even though it has mostly been superseded.

```php
$encrypted = \Dcrypt\AesOfb::encrypt($plaintext, $password);

$plaintext = \Dcrypt\AesOfb::decrypt($encrypted, $password);
```

### Custom Encryption Suites
Often it is useful to customize the encryption and authentication algorithms to fit a specific purpose.
Dcrypt offers two ways to extend the core encryption functionality.

#### Static Wrapper
Use any cipher/algo combination by calling the `OpensslStatic` class.

```php
$encrypted = \Dcrypt\OpensslStatic::encrypt($plaintext, $password, 'des-ofb', 'md5');

$plaintext = \Dcrypt\OpensslStatic::decrypt($encrypted, $password, 'des-ofb', 'md5');
```

To find supported options, `openssl_get_cipher_methods()` and `hash_algos()` are helpful.

#### Class Overloading
Dcrypt's internal functions are easily extendable by overloading the `OpensslBridge` class. 

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

```php
$encrypted = \TinyFish::encrypt($plaintext, $password, 10000);

$plaintext = \TinyFish::decrypt($encrypted, $password, 10000);
```

### Iterative HMAC Key Hardening
To reduce the effectiveness of brute-force cracking on your encrypted blobs, you can provide an integer `$cost` parameter in your encryption call. 
This integer will cause dcrypt to perform `$cost` number of extra HMAC operations on the key before passing it off to the underlying encryption system.
```php
$encrypted = \Dcrypt\AesCbc::encrypt($plaintext, $password, 10000);

$plaintext = \Dcrypt\AesCbc::decrypt($encrypted, $password, 10000);
```

### Tamper Protection
By default, a `InvalidArgumentException` will be thrown *before* decryption if the supplied checksum is not valid.
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
`Dcrypt\Hash` is an opaque 480 bit iterative hash function. 
First, SHA-256 is used to hash a 16 byte initialization vector with your secret password to create a unique key.
Then `$cost` number of are performed to on the password to create the final HMAC key.
The `$cost` parameter can be any integer between 1 and 2<sup>32</sup> and is stored as 4 encrypted bytes within the output.

```php
$hash = \Dcrypt\Hash::make($plaintext, $password, $cost);

$bool = \Dcrypt\Hash::verify($plaintext, $hash, $password);
```

## Time-safe String Comparison
Dcrypt uses time-safe string comparisons in all sensitive areas. The same function that is used internally is also exposed for use in your projects.
```php
$equals = \Dcrypt\Str::equal('known', 'given');
```

## ROT-128 Encoder
Just because I felt like it!
This function works like ROT-13 but uses entire bytes.
```php
$rotated = \Dcrypt\Rot128::flip("some data to rotate");

$original = \Dcrypt\Rot128::flip($rotated);
```

# Show me some love :heart_eyes:
Developing dcrypt has been a labor of love for many years. 
If you find dcrypt useful, please consider donating some Litecoin.
 
`LN97LrLCNiv14V6fntp247H2pj9UiFzUQZ`

 ![litecoin address](https://rawgit.com/mmeyer2k/dcrypt/master/litecoin.png)
