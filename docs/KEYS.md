# Guide to dcrypt keys

Dcrypt likes __BIG__ keys.
This document explains the reasoning behind this design decision and some tips on key management.

## Why 2048 bytes?

The large key size of 2048 bytes enables dcrypt to forgo any computationally wasteful (at best) and potentially dangerous (at worst) password derivation while still providing very strong security and brute force resistance.

At 2048 bytes the probability of every byte in the 0x00 to 0xFF range being used at least once in a pseudo-random string approaches 1.
This statistical curiosity can be leveraged to heuristically differentiate between strong and weak entropy sources.
Particularly, implementation mistakes like double encoding of the key can be rejected by ensuring that the byte stream uses most of the 2^8 keyspace.

Before encryption a basic key entropy test is performed which rejects keys that are not likely to be pseudo-random.
This test is not perfect but it is simple and fast, and it may become conditional in the future.

A primitive of the randomness heuristic is as follows:

```php
<?php

if (count(array_unique(str_split($key))) < 250) {
    throw InvalidKeyException;
}
```

## Create a new key

Command line to screen:

```bash
head -c 2048 /dev/urandom | base64 -w 0 | xargs echo
```

Command line to file:

```bash
head -c 2048 /dev/urandom | base64 -w 0 > /path/to/secret.key
```

PHP static function:

```php
<?php

$key = \Dcrypt\OpensslKey::create();

file_put_contents("~/secret.key", $key);
```

## Storage tips

Since the key is base64 encoded it can contain any whitespace you desire.
An optimal solution when using opcache is to store as a single file and use it in a `require` statement like so...

Content of `/path/to/secret.key`:

```php
<?php

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
