<?php declare(strict_types=1);

/**
 * support.php
 *
 * Displays supported
 */

require __DIR__ . '/../vendor/autoload.php';

$key = \Dcrypt\OpensslKeyGenerator::newKey();

echo "CIPHERS ----------------------------------------------------------------------------------------------" . PHP_EOL;

foreach (\openssl_get_cipher_methods() as $meth) {
    // Only process the lower case names
    if (strtolower($meth) !== $meth) {
        continue;
    }

    echo str_pad("[$meth]", 40);

    try {
        $e = \Dcrypt\OpensslStatic::encrypt('AAAA', $key, $meth, 'sha256');
        $d = \Dcrypt\OpensslStatic::decrypt($e, $key, $meth, 'sha256');

        echo " [pass] ";
    } catch (\Exception|\Error $e) {
        $m = $e->getMessage();
        echo " [fail] [$m]";
    } finally {
        echo "\n";
    }
}

echo "ALGOS ------------------------------------------------------------------------------------------------" . PHP_EOL;

foreach (hash_algos() as $algo) {
    // Only process the lower case names
    if (strtolower($algo) !== $algo) {
        continue;
    }

    try {
        $e = \Dcrypt\OpensslStatic::encrypt('AAAA', $key, 'aes-256-gcm', $algo);
        $d = \Dcrypt\OpensslStatic::decrypt($e, $key, 'aes-256-gcm', $algo);

        echo " [pass] ";
    } catch (\Exception|\Error $e) {
        $m = $e->getMessage();
        echo " [fail] [$m]";
    } finally {
        echo "\n";
    }
}
