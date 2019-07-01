<?php declare(strict_types=1);

/*
 * Generates the openssl-related test vectors in tests/vectors
 */

use \Dcrypt\OpensslStatic;

require __DIR__ . '/../vendor/autoload.php';

$key = \Dcrypt\OpensslKeyGenerator::newKey();

file_put_contents(__DIR__ . '/../tests/vectors/.testkey', $key);

$out = [];

foreach (\Dcrypt\OpensslSupported::ciphers() as $cipher) {
    if (strtolower($cipher) !== $cipher) {
        continue;
    }

    try {
        $out[$cipher] = base64_encode(OpensslStatic::encrypt('hello world', $key, $cipher, 'sha3-256'));
    } catch (\Exception|\Error $e) {

    }
}

file_put_contents(__DIR__ . '/../tests/vectors/openssl-static-ciphers.json', \json_encode($out, JSON_PRETTY_PRINT));

$out = [];

foreach (\Dcrypt\OpensslSupported::algos() as $algo) {
    if (strtolower($algo) !== $algo) {
        continue;
    }

    $out[$algo] = base64_encode(OpensslStatic::encrypt('hello world', $key, 'aes-256-gcm', $algo));
}

file_put_contents(__DIR__ . '/../tests/vectors/openssl-static-algos.json', \json_encode($out, JSON_PRETTY_PRINT));

$out = [];

foreach (range(1, 10) as $r) {
    $mult = $r * $r * 10;

    $out[$mult] = \base64_encode(\Dcrypt\Otp::crypt(str_repeat('A', $mult), $key));
}

file_put_contents(__DIR__ . '/../tests/vectors/otp.json', \json_encode($out, JSON_PRETTY_PRINT));