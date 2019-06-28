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
composer require "mmeyer2k/dcrypt=^10.0"
```

# Features
## Block Ciphers
Dcrypt helps application developers avoid common mistakes in crypto implementations that leave data at risk while providing flexibility in its options.
Dcrypt strives to make correct usage simple, but it is possible to use dcrypt incorrectly.

__NOTE__: Dcrypt's default configurations assume the usage of a base64 encoded high entropy key with a minimum of 2048 bits. 
Be sure to read the section on key hardening and pay close attention to the diffences between `$key` and `$password`.
To quickly generate a strong key execute this command line:
```bash
head -c 256 /dev/urandom | base64 -w 0 | xargs echo
```

### AES-256 GCM Encryption
PHP 7.1 ships with support for new AEAD encryption modes, GCM being considered the safest of these.
An AEAD authentication tag combined with SHA-256 HMAC ensures encrypted messages can not be forged or altered.

**When in doubt, use this example and don't read any further!**

```php
<?php
// Decode the high entropy key
$key = "replace this with the output of: head -c 256 /dev/urandom | base64 -w 0 | xargs echo";

$encrypted = \Dcrypt\Aes256Gcm::encrypt("a secret", $key);

$plaintext = \Dcrypt\Aes256Gcm::decrypt($encrypted, $key);
```

### Other AES-256 Modes

If you read to this point then you are an experienced cryptonaut, congrats :ok_hand: :metal:

Several AES-256 encryption modes are supported out of the box via hardcoded classes.

| Class Name           | OpenSSL Cipher   | Further Reading |
| -------------------- | :--------------: | --------------- |
| `\Dcrypt\Aes256Gcm`  |    `aes-256-gcm` | [wiki](https://en.wikipedia.org/wiki/Galois/Counter_Mode) |
| `\Dcrypt\Aes256Cbc`  |    `aes-256-cbc` | [wiki](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) |
| `\Dcrypt\Aes256Ctr`  |    `aes-256-ctr` | [wiki](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)) |
| `\Dcrypt\Aes256Ecb`  |    `aes-256-ecb` | [wiki](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB) |

### Custom Encryption Suites

Dcrypt is compatible with _most_ OpenSSL ciphers and hashing algorithms supported by PHP.


#### Static Wrapper

Use any cipher/algo combination by calling the `OpensslStatic` class.

```php
<?php
$encrypted = \Dcrypt\OpensslStatic::encrypt("a secret", $key, 'des-ofb', 'md5');

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
$encrypted = \BlowfishCrc::encrypt("a secret", $password);

$plaintext = \BlowfishCrc::decrypt($encrypted, $password);
```

### Message Authenticity Checking
By default, a `\Dcrypt\Exceptions\InvalidChecksum` exception will be thrown before decryption is allowed to proceed when the supplied checksum is not valid.

```php
<?php
$encrypted = \Dcrypt\Aes256Gcm::encrypt("a secret", $key);

// Mangle the encrypted data by adding a single character
$encrypted = $encrypted . 'A';

try {
    $decrypted = \Dcrypt\Aes256Gcm::decrypt($encrypted, $key);
} catch (\Dcrypt\Exceptions\InvalidChecksumException $ex) {
    // ...
}
```

### PBKDF2 Key Hardening

Key-based encryption mode is preferred because the iterative PBKDF2 hardening process can be skipped, reducing overhead.
If using strong keys never use these options.

When using a source of low entropy for the password/key (or "passkey") parameter, a `$cost` value of appropriate size _must_ be chosen based on the requirements of the application.
High cost values could lead to DoS attacks if used improperly for your application, use caution when selecting this number.

The PBKDF2 cost can be defined in a custom class...
```php
<?php

class Aes256GcmWithCost extends \Dcrypt\OpensslBridge 
{
    const COST = 1000000;
}
```

or by passing a third parameter to the (en|de)crypt calls.
The `$cost` parameter always overloads any value stored in the class's `const COST`.

```php
<?php
$encrypted = \Dcrypt\Aes256Gcm::encrypt('a secret', $password, 10000);

$plaintext = \Dcrypt\Aes256Gcm::decrypt($encrypted, $password, 10000);
```

### Layered Encryption Factory

Feeling paranoid?
Is the NSA monitoring your brainwaves?
Not sure which cipher method you can trust?
Why not try all of them?

```php
<?php
$stack = (new \Dcrypt\OpensslStack($key))
    ->add('aes-256-ecb', 'snefru')
    ->add('aes-256-cfb', 'snefru256')
    ->add('aes-256-ofb', 'sha224')
    ->add('aes-256-cbc', 'sha256')
    ->add('aes-256-ctr', 'sha384')
    ->add('aes-256-gcm', 'sha512');

$encrypted = $stack->encrypt("a secret");

$plaintext = $stack->decrypt($encrypted);
```

## Stream Ciphers

Be sure you understand the risks and inherent issues of using a stream cipher before proceeding.

### One Time Pad Encryption

A fast symmetric stream cipher is quickly accessible with the `Otp` class.
`Otp` uses SHA-512 to output a keystream that is ⊕'d with the input in 512 bit chunks.


```php
<?php
$encrypted = \Dcrypt\Otp::crypt("a secret", $key);

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
$encrypted = \Dcrypt\Rc4::crypt('a secret', $password);

$plaintext = \Dcrypt\Rc4::crypt($encrypted, $password);
```
```php
<?php
$encrypted = \Dcrypt\Spritz::crypt('a secret', $password);

$plaintext = \Dcrypt\Spritz::crypt($encrypted, $password);
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
