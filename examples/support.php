<?php

declare(strict_types=1);

error_reporting(0);

/**
 * support.php.
 *
 * Displays supported ciphers and algos
 */
require __DIR__.'/../vendor/autoload.php';

$key = \Dcrypt\OpensslKey::create();

echo "\nCIPHERS ----------------------------------------------------------------------------------------------\n";

foreach (\openssl_get_cipher_methods() as $meth) {
    // Only process the lower case names
    if (\strtolower($meth) !== $meth) {
        continue;
    }

    echo \str_pad("[$meth]", 40);

    try {
        $e = \Dcrypt\OpensslStatic::encrypt('AAAA', $key, $meth, 'sha256');
        $d = \Dcrypt\OpensslStatic::decrypt($e, $key, $meth, 'sha256');

        echo ' [pass] ';
    } catch (\Exception | \Error $e) {
        $m = $e->getMessage();
        echo ' [fail] [!!!]';
    } finally {
        echo "\n";
    }
}

echo "\nALGOS ------------------------------------------------------------------------------------------------\n";

foreach (\hash_algos() as $algo) {
    // Only process the lower case names
    if (\strtolower($algo) !== $algo) {
        continue;
    }

    echo \str_pad("[$algo]", 40);

    try {
        $e = \Dcrypt\OpensslStatic::encrypt('AAAA', $key, 'aes-256-gcm', $algo);
        $d = \Dcrypt\OpensslStatic::decrypt($e, $key, 'aes-256-gcm', $algo);

        echo ' [pass] ';
    } catch (\Exception | \Error $e) {
        $m = $e->getMessage();
        echo ' [fail] [!!!]';
    } finally {
        echo "\n";
    }
}
