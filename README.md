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
- [Show me some love](#show-me-some-love-heart_eyes) :heart_eyes::beer:

# Install
Add dcrypt to your composer.json file requirements.
Don't worry, dcrypt does not have any dependencies of its own.
```bash
composer require "mmeyer2k/dcrypt=^11.0"
```

# Features

## Block Ciphers

The dcrypt library helps application developers avoid common mistakes in crypto implementations that leave data at risk while still providing flexibility in its options for crypto enthusiasts.
Dcrypt strives to make correct usage simple, but it _is_ possible to use dcrypt incorrectly.
Fully understanding the instructions is important.

Dcrypt's functions require the use of a 256 byte (minimum) key encoded with base64.
To generate and encode a new key execute this command line:

```bash
head -c 256 /dev/urandom | base64 -w 0 | xargs echo
```

### AES-256 GCM Encryption

PHP 7.1 ships with support for new AEAD encryption modes, GCM being considered the safest of these.
Dcrypt will handle the 32 bit AEAD authentication tag, SHA3-256 HMAC and initialization vector as a single string.

```php
<?php
$key = "replace this with the output of: head -c 256 /dev/urandom | base64 -w 0 | xargs echo";

$encrypted = \Dcrypt\Aes256Gcm::encrypt('a secret', $key);

$plaintext = \Dcrypt\Aes256Gcm::decrypt($encrypted, $key);
```

**If in doubt, use this example and don't read any further!**

### Other AES-256 Modes

If you read to this point then you are an experienced cryptonaut, congrats! :ok_hand: :metal:

Several AES-256 encryption modes are supported out of the box via hardcoded classes.

| Class Name           | OpenSSL Cipher   | Further Reading |
| -------------------- | :--------------: | --------------- |
| `\Dcrypt\Aes256Gcm`  |    `aes-256-gcm` | [wiki](https://en.wikipedia.org/wiki/Galois/Counter_Mode) |
| `\Dcrypt\Aes256Cbc`  |    `aes-256-cbc` | [wiki](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) |
| `\Dcrypt\Aes256Ctr`  |    `aes-256-ctr` | [wiki](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)) |
| `\Dcrypt\Aes256ofb`  |    `aes-256-ofb` | [wiki](https://en.wikipedia.org/wiki/Galois/Counter_Mode) |
| `\Dcrypt\Aes256Ecb`  |    `aes-256-ecb` | [wiki](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB) |

### Custom Encryption Suites

Dcrypt is compatible with _most_ OpenSSL ciphers and hashing algorithms supported by PHP.
Run `php examples/support.php` to view supported options.

#### Static Wrapper

Use any cipher/algo combination by calling the `OpensslStatic` class.

```php
<?php
$encrypted = \Dcrypt\OpensslStatic::encrypt('a secret', $key, 'des-ofb', 'md5');

$plaintext = \Dcrypt\OpensslStatic::decrypt($encrypted, $key, 'des-ofb', 'md5');
```

#### Class Overloading

Dcrypt's internal functions are easily extendable by overloading the `OpensslBridge` class. 

```php
<?php

class BlowfishCrc extends \Dcrypt\OpensslBridge 
{
    const CIPHER = 'bf-ofb';

    const ALGO = 'crc32';
}
```

then...

```php
<?php
$encrypted = \BlowfishCrc::encrypt('a secret', $key);

$plaintext = \BlowfishCrc::decrypt($encrypted, $key);
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

### Layered Encryption Factory

Feeling especially paranoid?
Is the NSA monitoring your brainwaves?
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

## Stream Ciphers

Be sure you understand the risks and inherent issues of using a stream cipher before proceeding.

### One Time Pad Encryption

A fast symmetric stream cipher is quickly accessible with the `Otp` class.
`Otp` uses SHA3-512 to output a keystream that is ⊕'d with the input in 512 bit chunks.


```php
<?php
$encrypted = \Dcrypt\Otp::crypt('a secret', $key);

$plaintext = \Dcrypt\Otp::crypt($encrypted, $key);
```

`Otp` can also be configured to use any other hashing algorithm to generate the pseudorandom keystream.
```php
<?php
$encrypted = \Dcrypt\Otp::crypt('a secret', $key, 'whirlpool');

$plaintext = \Dcrypt\Otp::crypt($encrypted, $key, 'whirlpool');
```

### Rivest's Ciphers

`\Dcrypt\Rc4` and `\Dcrypt\Spritz` are pure PHP implementations of the immortal [RC4](https://en.wikipedia.org/wiki/RC4) cipher and its successor [Spritz](https://people.csail.mit.edu/rivest/pubs/RS14.pdf).

```php
<?php
$encrypted = \Dcrypt\Rc4::crypt('a secret', $key);

$plaintext = \Dcrypt\Rc4::crypt($encrypted, $key);
```
```php
<?php
$encrypted = \Dcrypt\Spritz::crypt('a secret', $key);

$plaintext = \Dcrypt\Spritz::crypt($encrypted, $key);
```

**NOTE**: 
These implementations are for reference only and are fully marked as `@deprecated`. 
The RC4 cipher in general has many known security problems, and the Spirtz implementation provided here has not been verified against known test vectors. 
Both are very slow and inefficient.
This was just for fun.

**NOTE**: 
Backwards compatibility breaking changes to these classes will not result in an incremented major version number.

# Show me some love :heart_eyes::beer:
Developing dcrypt has been a great journey for many years.
If you find dcrypt useful, please consider donating some Litecoin.
 
`LN97LrLCNiv14V6fntp247H2pj9UiFzUQZ`

 ![litecoin address](https://mmeyer2k.github.io/images/litecoin-wallet.png)
