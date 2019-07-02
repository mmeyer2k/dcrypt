# Guide to dcrypt keys

Dcrypt likes __BIG__ keys.
This document explains some of the reasoning behind these design decisions and some tips on handling keys.

## Why 2048 bytes though?

At 2048 bytes the probability of any byte in the 0x00 to 0xFF range being used at least once approaches 1.
Unless, of course, a source of low entropy were used for the initial keying material.

A basic test is performed at run time to indicate whether the key is likely to be pseudorandom.
An exception is raised if the key does not pass this test.
This test is not perfect but it is simple and fast.
It may become conditional in the future.

A generic of the randomness test is this as follows:

```php
<?php
if (\count(\array_unique(\str_split($key))) < 250) {
    // throw exception
}
```

The large size of 2048 bytes safely allows us to forgo computationally wasteful and potentially dangerous password derivation while still providing strong security.

## Create a new key

Command line to screen:

```bash
head -c 2048 /dev/urandom | base64 -w 0 | xargs echo
```

Command line to file:

```bash
head -c 2048 /dev/urandom | base64 -w 0 > ~/secret.key
```

PHP static function:

```php
<?php

$key = \Dcrypt\OpensslKey::create();

file_put_contents("~/secret.key", $key);
```

## Storage tips

Since the key is base64 encoded it can contain any whitespace you desire.
An optimal solution when using opcache is to store as a single file and use it in a `require` statement.

```php
<?php

# content of /path/to/secret.key

return <<<EOT

key....................................................
key....................................................
key....................................................
key....................................................
key....................................................

EOT;

```

then...

```php
<?php

$key = require '/path/to/secret.key';
```

Keys can also be stored in environment files, functions, and class properties.
