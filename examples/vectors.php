<?php declare(strict_types=1);

use \Dcrypt\OpensslStatic;

require __DIR__ . '/../vendor/autoload.php';

$abcd = OpensslStatic::encrypt('hello', 'world', 'aes-256-cbc', 'sha256', 10);
$efgh = OpensslStatic::decrypt($abcd, 'world', 'aes-256-cbc', 'sha256', 10);

$out = [];

foreach (\Dcrypt\OpensslSupported::ciphers() as $cipher) {
    $cipher = strtolower($cipher);
    if (isset($out[$cipher])) {
        continue;
    }
    $out[$cipher] = base64_encode(OpensslStatic::encrypt('hello', 'world', $cipher, 'sha256', 10));
}

file_put_contents(__DIR__ . '/../tests/vectors/openssl-static-ciphers.json', \json_encode($out, JSON_PRETTY_PRINT));

$out = [];

foreach (\Dcrypt\OpensslSupported::algos() as $algo) {
    $cipher = strtolower($algo);
    if (isset($out[$algo])) {
        continue;
    }
    $out[$algo] = base64_encode(OpensslStatic::encrypt('hello', 'world', 'aes-256-gcm', $algo, 10));
}

file_put_contents(__DIR__ . '/../tests/vectors/openssl-static-algos.json', \json_encode($out, JSON_PRETTY_PRINT));