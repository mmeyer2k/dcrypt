:closed_lock_with_key:dcrypt
======
[![StyleCI](https://github.styleci.io/repos/22845594/shield?style=flat)](https://github.styleci.io/repos/22845594)
[![Build Status](https://circleci.com/gh/mmeyer2k/dcrypt/tree/master.svg?style=shield)](https://circleci.com/gh/mmeyer2k/dcrypt)
[![Code Coverage](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/?branch=master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/?branch=master)
[![Code Climate GPA](https://codeclimate.com/github/mmeyer2k/dcrypt/badges/gpa.svg)](https://codeclimate.com/github/mmeyer2k/dcrypt)
[![License](https://poser.pugx.org/mmeyer2k/dcrypt/license.svg)](https://packagist.org/packages/mmeyer2k/dcrypt)
[![Latest Stable Version](https://poser.pugx.org/mmeyer2k/dcrypt/version)](https://packagist.org/packages/mmeyer2k/dcrypt)

A petite library of essential encryption functions for PHP 7.1+.
For legacy PHP version support, look [here](https://github.com/mmeyer2k/dcrypt/blob/master/docs/LEGACY.md).
If you need a dcrypt inspired encryption library for .NET, check out [harpocrates](https://github.com/mmeyer2k/harpocrates).

# Install

Add dcrypt to your composer.json file requirements.
Don't worry, dcrypt does not have any dependencies of its own.

```bash
composer require "mmeyer2k/dcrypt:^14.0"
```

## Block Ciphers

The dcrypt library helps application developers avoid common mistakes in crypto implementations that leave data at risk.

[Specification document](https://github.com/mmeyer2k/dcrypt/blob/master/docs/CRYPTO.md)

### Keys

Safe usage of dcrypt's block cipher functions requires the use of a high entropy 256 bit (minimum) key.
Keys should be passed into dcrypt in *base64* encoded format. 
**You are responsible for the randomness of your key!**

Generate a new key on the linux CLI:

```bash
head -c 32 /dev/urandom | base64 -w 0 | xargs echo
```

Or with PHP...
```php
<?php
$key = \Dcrypt\OpensslKey::create(32);
```

### AES-256 GCM Encryption

Since PHP 7.1 supports native AEAD encryption modes, using GCM would be safest option for most applications.
Dcrypt will handle the AEAD authentication tag, [SHA3](https://en.wikipedia.org/wiki/SHA-3)-256 HMAC, initialization vector and encrypted message as a single unencoded string.

```php
<?php
$key = \Dcrypt\OpensslKey::create(32);

$encrypted = \Dcrypt\Aes::encrypt('a secret', $key);

$plaintext = \Dcrypt\Aes::decrypt($encrypted, $key);
```

**If in doubt, use this example and don't read any further!**

### Other AES-256 Modes

If you read to this point then you are an experienced cryptonaut, congrats! :ok_hand: :metal:

Several AES-256 encryption modes are supported out of the box via hardcoded classes.

| Class Name            | OpenSSL Cipher   | Security Rating   | Further Reading |
| --------------------  | :--------------: | :---------------: | --------------- |
| `Aes256Gcm` or `Aes`  |    `aes-256-gcm` | :smiley:          | [wiki](https://en.wikipedia.org/wiki/Galois/Counter_Mode) |
| `Aes256Ctr`           |    `aes-256-ctr` | :relaxed:         | [wiki](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)) |
| `Aes256Cbc`           |    `aes-256-cbc` | :expressionless:  | [wiki](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) |
| `Aes256Ofb`           |    `aes-256-ofb` | :grimacing:       | [wiki](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_Feedback_(OFB)) |
| `Aes256Cfb`           |    `aes-256-cfb` | :hushed:          | [wiki](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Feedback_(CFB)) |
| `Aes256Ccm`           |    `aes-256-ccm` | :astonished:      | [wiki](https://en.wikipedia.org/wiki/CCM_mode) |
| `Aes256Ecb`           |    `aes-256-ecb` | :rage:            | [wiki](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB) |

### Custom Encryption Suites

Dcrypt is compatible with _most_ OpenSSL ciphers and hashing algorithms supported by PHP.
Run `openssl_get_cipher_methods()` and `hash_algos()` to view supported options on your platform.

#### Static Wrapper

Use any cipher/algo combination by calling the `OpensslStatic` class.

```php
<?php
$encrypted = \Dcrypt\OpensslStatic::encrypt('a secret', $key, 'bf-ofb', 'crc32');

$plaintext = \Dcrypt\OpensslStatic::decrypt($encrypted, $key, 'bf-ofb', 'crc32');
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

$encrypted = BlowfishCrc32::encrypt('a secret', $key);

$plaintext = BlowfishCrc32::decrypt($encrypted, $key);
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
try {
    $decrypted = \Dcrypt\Aes::decrypt('malformed cyphertext', $key);
} catch (\Dcrypt\Exceptions\InvalidChecksumException $ex) {
    // ...
}
```

## Stream Ciphers

Be sure you understand the risks and inherent issues of using a stream cipher before proceeding.

- Each key should only be used once
- Data integrity can not be guaranteed
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

## String Helpers

Generate random base62 string tokens with specified number of characters.
```php
$token = \Dcrypt\Str::token(10);
```

Compare 2 strings in a time-safe manner.
```php
$equal = \Dcrypt\Str::equal($known, $given);
```

## Show me some love :heart_eyes::beer:

Developing dcrypt has been a great journey for many years.
If you find dcrypt useful, please consider donating.
 
__`LTC: LN97LrLCNiv14V6fntp247H2pj9UiFzUQZ`__
__`BTC: 3N7vhA6ghWb1VrP4nGA6m6mzA9T2ASCVEj`__
__`ETH: 0xe14a56046f28fCEF56A0EA4a84973bDdFF546923`__
