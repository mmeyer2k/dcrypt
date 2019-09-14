:closed_lock_with_key:dcrypt
======
[![Build Status](https://circleci.com/gh/mmeyer2k/dcrypt/tree/master.svg?style=shield)](https://circleci.com/gh/mmeyer2k/dcrypt)
[![Code Coverage](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/?branch=master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/?branch=master)
[![Code Climate GPA](https://codeclimate.com/github/mmeyer2k/dcrypt/badges/gpa.svg)](https://codeclimate.com/github/mmeyer2k/dcrypt)
[![License](https://poser.pugx.org/mmeyer2k/dcrypt/license.svg)](https://packagist.org/packages/mmeyer2k/dcrypt)
[![Latest Stable Version](https://poser.pugx.org/mmeyer2k/dcrypt/version)](https://packagist.org/packages/mmeyer2k/dcrypt)
[![StyleCI](https://github.styleci.io/repos/22845594/shield?style=flat)](https://github.styleci.io/repos/22845594)

A petite library of essential encryption functions for PHP 7.1+.
For legacy PHP version support, look [here](https://github.com/mmeyer2k/dcrypt/blob/master/docs/LEGACY.md).

- [Install](#install)
- [Features](#features)
  - [Block Ciphers](#block-ciphers)
    - [AES-256 GCM Encryption](#aes-256-gcm-encryption)
    - [Other AES-256 Modes](#other-aes-256-modes)
    - [Custom Encryption Suites](#custom-encryption-suites)
      - [Static Wrapper](#static-wrapper)
      - [Class Overloading](#class-overloading)
      - [Layered Encryption Factory](#layered-encryption-factory)
    - [Message Authenticity Checking](#message-authenticity-checking)
  - [Stream Ciphers](#stream-ciphers)
    - [One Time Pad](#one-time-pad)
- [Show me some love](#show-me-some-love-heart_eyes) :heart_eyes::beer:

# Install

Add dcrypt to your composer.json file requirements.
Don't worry, dcrypt does not have any dependencies of its own.

```bash
composer require "mmeyer2k/dcrypt=^13.0"
```

# Features

## Block Ciphers

The dcrypt library helps application developers avoid common mistakes in crypto implementations that leave data at risk while still providing flexibility in its options for crypto enthusiasts.
Dcrypt strives to make correct usage simple, but it _is_ possible to use dcrypt incorrectly.
Fully understanding the instructions is important.

Dcrypt's functions __require__ the use of a high entropy __2048 byte__ (minimum) key encoded with base64.
To generate a new key, execute this on the command line:

```bash
head -c 2048 /dev/urandom | base64 -w 0 | xargs echo
```

Storing this key safely is up to you! [Guide to keys](https://github.com/mmeyer2k/dcrypt/blob/master/docs/KEYS.md).

[Specification document](https://github.com/mmeyer2k/dcrypt/blob/master/docs/CRYPTO.md)


### AES-256 GCM Encryption

Since PHP 7.1 supports native AEAD encryption modes, using GCM would be safest option for most applications.
Dcrypt will handle the AEAD authentication tag, SHA3-256 HMAC ([Keccak](https://en.wikipedia.org/wiki/SHA-3)), initialization vector and encrypted message as a single unencoded string.

```php
<?php
$key = "replace this with the output of: head -c 2048 /dev/urandom | base64 -w 0 | xargs echo";

$encrypted = \Dcrypt\Aes256Gcm::encrypt('a secret', $key);

$plaintext = \Dcrypt\Aes256Gcm::decrypt($encrypted, $key);
```

**If in doubt, use this example and don't read any further!**

### Other AES-256 Modes

If you read to this point then you are an experienced cryptonaut, congrats! :ok_hand: :metal:

Several AES-256 encryption modes are supported out of the box via hardcoded classes.

| Class Name           | OpenSSL Cipher   | Security Rating   | Further Reading |
| -------------------- | :--------------: | :---------------: | --------------- |
| `\Dcrypt\Aes256Gcm`  |    `aes-256-gcm` | :smiley:          | [wiki](https://en.wikipedia.org/wiki/Galois/Counter_Mode) |
| `\Dcrypt\Aes256Ctr`  |    `aes-256-ctr` | :relaxed:         | [wiki](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)) |
| `\Dcrypt\Aes256Cbc`  |    `aes-256-cbc` | :expressionless:  | [wiki](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) |
| `\Dcrypt\Aes256Ofb`  |    `aes-256-ofb` | :grimacing:       | [wiki](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_Feedback_(OFB)) |
| `\Dcrypt\Aes256Cfb`  |    `aes-256-cfb` | :hushed:          | [wiki](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Feedback_(CFB)) |
| `\Dcrypt\Aes256Ccm`  |    `aes-256-ccm` | :astonished:      | [wiki](https://en.wikipedia.org/wiki/CCM_mode) |
| `\Dcrypt\Aes256Ecb`  |    `aes-256-ecb` | :rage:            | [wiki](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB) |

### Custom Encryption Suites

Dcrypt is compatible with _most_ OpenSSL ciphers and hashing algorithms supported by PHP.
Run `php examples/support.php` to view supported options.

#### Static Wrapper

Use any cipher/algo combination by calling the `OpensslStatic` class.

```php
<?php
$encrypted = \Dcrypt\OpensslStatic::encrypt('a secret', $key, 'bf-ofb', 'crc32');

$plaintext = \Dcrypt\OpensslStatic::decrypt($encrypted, $key, 'bf-ofb', 'crc32');
```

then...

```php
<?php
$encrypted = \BlowfishCrc32::encrypt('a secret', $key);

$plaintext = \BlowfishCrc32::decrypt($encrypted, $key);
```

#### Class Overloading

Dcrypt's internal functions are easily extendable by overloading the `OpensslBridge` class. 

```php
<?php

class BlowfishCrc32 extends \Dcrypt\OpensslBridge 
{
    const CIPHER = 'bf-ofb';

    const ALGO = 'crc32';
}
```

#### Layered Encryption Factory

Feeling especially paranoid?
Not sure which cipher methods and algos can be trusted?
Why not try all of them.

```php
<?php
$stack = (new \Dcrypt\OpensslStack($key))
    ->add('aes-256-ecb', 'snefru')
    ->add('aes-256-ofb', 'sha224')
    ->add('aes-256-cbc', 'sha256')
    ->add('aes-256-ctr', 'sha384')
    ->add('aes-256-gcm', 'sha512');

$encrypted = $stack->encrypt('a secret');

$plaintext = $stack->decrypt($encrypted);
```

### Message Authenticity Checking

By default, `\Dcrypt\Exceptions\InvalidChecksumException` exception will be raised before decryption is allowed to proceed when the supplied checksum is not valid.

```php
<?php
$encrypted = \Dcrypt\Aes256Gcm::encrypt('a secret', $key);

// Mangle the encrypted data by adding a single character
$encrypted = $encrypted . 'A';

try {
    $decrypted = \Dcrypt\Aes256Gcm::decrypt($encrypted, $key);
} catch (\Dcrypt\Exceptions\InvalidChecksumException $ex) {
    // ...
}
```

## Stream Ciphers

Be sure you understand the risks and inherent issues of using a stream cipher before proceeding.

- Each key should only be used once
- No checksums mean data can be forged or altered
- [https://en.wikipedia.org/wiki/Stream_cipher_attacks](https://en.wikipedia.org/wiki/Stream_cipher_attacks)
- [https://jameshfisher.com/2018/01/01/making-a-stream-cipher/](https://jameshfisher.com/2018/01/01/making-a-stream-cipher/)

### One Time Pad

A novel counter-based stream cipher.
`OneTimePad` uses SHA3-512 to output a keystream that is ⊕'d with the input in 512 bit chunks.

[Specification document](https://github.com/mmeyer2k/dcrypt/blob/master/docs/ONETIMEPAD.md)

```php
<?php
$encrypted = \Dcrypt\OneTimePad::crypt('a secret', $key);

$plaintext = \Dcrypt\OneTimePad::crypt($encrypted, $key);
```

`OneTimePad` can use any hashing algorithm to generate the pseudorandom keystream.

```php
<?php
$encrypted = \Dcrypt\OneTimePad::crypt('a secret', $key, 'whirlpool');

$plaintext = \Dcrypt\OneTimePad::crypt($encrypted, $key, 'whirlpool');
```

# Show me some love :heart_eyes::beer:

Developing dcrypt has been a great journey for many years.
If you find dcrypt useful, please consider donating some Litecoin.
 
__`LN97LrLCNiv14V6fntp247H2pj9UiFzUQZ`__

 ![litecoin address](https://mmeyer2k.github.io/images/litecoin-wallet.png)
