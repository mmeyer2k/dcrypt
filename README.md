:closed_lock_with_key:dcrypt
======
[![Total Downloads](https://poser.pugx.org/mmeyer2k/dcrypt/downloads)](https://packagist.org/packages/mmeyer2k/dcrypt)
[![Build Status](https://circleci.com/gh/mmeyer2k/dcrypt/tree/master.svg?style=shield)](https://circleci.com/gh/mmeyer2k/dcrypt)
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

__NOTE__: Dcrypt's default configurations assume the usage of a high entropy key. 
Be sure to read the section on key hardening and pay close attention to the diffences between `$key` and `$password`.

### AES-256-GCM Encryption
PHP 7.1 comes with support for new AEAD encryption modes, GCM being considered the best of these.
Small authentication tags are selected because dcrypt already provides SHA-256 HMAC based authentication.
Using this mode essentially adds an extra 32 bit checksum to the ciphertext.
**When in doubt, use this class**

```php
$key = base64_decode("some high entropy base64 encoded keying material");

$encrypted = \Dcrypt\Aes256Gcm::encrypt($plaintext, $key);

$plaintext = \Dcrypt\Aes256Gcm::decrypt($encrypted, $key);
```

### Other AES-256 Modes

Other AES-256 encryption modes are supported out of the box.
Only use modes other than GCM if you have a specific reason!

| Class Name           | OpenSSL Cipher   | Further Reading |
| -------------------- | :--------------: | --------------- |
| `\Dcrypt\Aes256Gcm`  |    `aes-256-gcm` | [wikipedia](https://en.wikipedia.org/wiki/Galois/Counter_Mode)               |
| `\Dcrypt\Aes256Cbc`  |    `aes-256-cbc` | [wikipedia](https://en.wikipedia.org/wiki/Galois/Counter_Mode)                |
| `\Dcrypt\Aes256Ctr`  |    `aes-256-ctr` | [wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR))                |
| `\Dcrypt\Aes256Ecb`  |    `aes-256-ecb` | [wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB)                |

### Custom Encryption Suites
Often it is useful to customize the encryption and authentication algorithms to fit a specific purpose.
Dcrypt offers two ways to extend the core encryption functionality.

#### Static Wrapper
Use any cipher/algo combination by calling the `OpensslStatic` class.

```php
$encrypted = \Dcrypt\OpensslStatic::encrypt($plaintext, $key, 'des-ofb', 'md5');

$plaintext = \Dcrypt\OpensslStatic::decrypt($encrypted, $key, 'des-ofb', 'md5');
```

To find supported options, `openssl_get_cipher_methods()` and `hash_algos()` are helpful.

#### Class Overloading
Dcrypt's internal functions are easily extendable by overloading the `OpensslBridge` class. 

```php
<?php

class BlowfishCrc extends \Dcrypt\OpensslBridge 
{
    const CIPHER = 'bf-ofb';

    const ALGO = 'crc32';

    const COST = 1000;
}
```

```php
$encrypted = \BlowfishCrc::encrypt($plaintext, $password);

$plaintext = \BlowfishCrc::decrypt($encrypted, $password);
```

### PBKDF2 Key Hardening
When using a source of low entropy for the password/key (or "passkey") parameter, a `$cost` value of appropriate size should be chosen based on the requirements of the application.
As a general rule, consider using a `$cost` number when the passkey contains less entropy than the selected hashing algorithm.
**A cost value of `0` is default, which assumes the usage of a high entropy password.**

Extremely high cost values could lead to DoS attacks if used improperly, use caution when selecting this number.

Easily generate a new key on the command line with:
```bash

```

```php
$encrypted = \Dcrypt\Aes256Gcm::encrypt($plaintext, $password);

$plaintext = \Dcrypt\Aes256Gcm::decrypt($encrypted, $password);
```

### Tamper Protection
By default, a `\Dcrypt\Exceptions\InvalidChecksum` exception will be thrown before decryption if the supplied checksum is not valid.
```php
try {
    $decrypted = \Dcrypt\AesCtr::decrypt($badInput, $key);
} catch (\Dcrypt\Exceptions\InvalidChecksum $ex) {
    // ...
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
These implementations are for reference only and are marked as `@deprecated`. 
The RC4 cipher in general has many known security problems, and the Spirtz implementation provided here has not been verified against known test vectors. 
Both are very slow and inefficient. 
This was just for fun. 
Use block ciphers for anything important.

**NOTE**: 
Backwards compatibility breaking changes to these classes will not result in an incremented major version number.

# Show me some love :heart_eyes:
Developing dcrypt has been a labor of love for many years. 
If you find dcrypt useful, please consider donating some Litecoin.
 
`LN97LrLCNiv14V6fntp247H2pj9UiFzUQZ`

 ![litecoin address](https://mmeyer2k.github.io/images/litecoin-wallet.png)
