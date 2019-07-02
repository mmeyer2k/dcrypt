# A guide to dcrypt keys

Garbage in, garbage out.

## Create a new key

Command line:
```bash
head -c 2048 /dev/urandom | base64 -w 0 | xargs echo
```

PHP static function:

```php
<?php

$key = \Dcrypt\OpensslKey::create();
```

## How entropy is determined