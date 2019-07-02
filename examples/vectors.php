<?php declare(strict_types=1);

/*
 * Generates the openssl-related test vectors in tests/.vectors.json
 */

use \Dcrypt\OpensslStatic;

require __DIR__ . '/../vendor/autoload.php';

$key = \Dcrypt\OpensslKey::create();

file_put_contents(__DIR__ . '/../tests/vectors/.testkey', $key);

$out = [
    'key' => $key,
    'algos' => [],
    'ciphers' => [],
    'aes256' => [],
    'otp' => [],
];

foreach (\Dcrypt\OpensslSupported::ciphers() as $cipher) {
    if (strtolower($cipher) !== $cipher) {
        continue;
    }

    try {
        $out['ciphers'][$cipher] = base64_encode(OpensslStatic::encrypt('a secret', $key, $cipher, 'sha3-256'));
    } catch (\Exception|\Error $e) {

    }
}

foreach (\Dcrypt\OpensslSupported::algos() as $algo) {
    if (strtolower($algo) !== $algo) {
        continue;
    }

    $out['algos'][$algo] = base64_encode(OpensslStatic::encrypt('a secret', $key, 'aes-256-gcm', $algo));
}

foreach(['Gcm', 'Ctr', 'Ofb', 'Cbc', 'Ecb'] as $mode){
    $c = "\\Dcrypt\\Aes256$mode";
    $out['aes256'][$c] = base64_encode($c::encrypt('a secret', $key));
}

foreach (range(1, 10) as $r) {
    $mult = $r * $r * 10;

    $out['otp'][$mult] = \base64_encode(\Dcrypt\Otp::crypt(str_repeat('A', $mult), $key));
}

file_put_contents(__DIR__ . '/../tests/.vectors.json', \json_encode($out, JSON_PRETTY_PRINT));