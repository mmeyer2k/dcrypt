dcrypt
======
[![Build Status](https://travis-ci.org/mmeyer2k/dcrypt.png)](https://travis-ci.org/mmeyer2k/dcrypt)
[![Code Coverage](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/?branch=master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/mmeyer2k/dcrypt/?branch=master)
[![Code Climate GPA](https://codeclimate.com/github/mmeyer2k/dcrypt/badges/gpa.svg)](https://codeclimate.com/github/mmeyer2k/dcrypt)
[![License](https://poser.pugx.org/mmeyer2k/dcrypt/license.svg)](https://packagist.org/packages/mmeyer2k/dcrypt)

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
# Features
## AES
Quickly access encryption functionality with the AES class. Functions use PHP's Mcrypt module with AES 256 bit cypher in CBC mode. Random IV and HMAC check-sum validation is done for you.
```php
$encrypted = Dcrypt\Aes::encrypt($input, $password);

# outputs a long encrypted hex string
echo bin2hex($encrypted);

# outputs your original plain text
echo Dcrypt\Aes::decrypt($encrypted, $password);
```
Supports the following mcrypt modes: `MCRYPT_MODE_CBC`, `MCRYPT_MODE_CFB`, `MCRYPT_MODE_ECB`, `MCRYPT_MODE_OFB`, `MCRYPT_MODE_NOFB`

## Fast One Time Pad Encryption
Extremely fast symmetric stream encryption is available with the `Otp` class.
```php
$crypted = Dcrypt\Otp::crypt('plaintext', 'key');

# outputs binary string 0x37e6e265adc272564b
echo $crypted;

# outputs 'plaintext'
echo Dcrypt\Otp::crypt($crypted, 'key'); 
```
## PKCS #7 Padding
PKCS#7 style padding is available via the `Pkcs7::pad()` and `Pkcs7::unpad()` functions.
## Strong Authenticated Key Derivation Function
```php
$hash = Dcrypt\Hash::make('plaintext', 'key');

# outputs binary string similar to 0x7d9cfc79ed7a72b322718c607c2f75dacd4a4824ad09c9f1ac0b43b5b9333ca031d9421742d968090097733a71524aa18c371d62082210a52b7e0d5eb0d5386d
echo $hash;

# to verify hashes, use Hash::verify()
$verified = Dcrypt\Hash::verify('plaintext', $hash, 'key');
```
