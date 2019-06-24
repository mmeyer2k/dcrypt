<?php

require __DIR__ . '/../vendor/autoload.php';

$out = [];

foreach (\Dcrypt\OpensslSupported::ciphers() as $cipher) {
    $out[strtolower($cipher)] = base64_encode(\Dcrypt\OpensslStatic::encrypt('hello', 'world', $cipher, 'sha256', 1));
}

file_put_contents(__DIR__ . '/../tests/vectors/openssl-static-ciphers.json', \json_encode($out, JSON_PRETTY_PRINT));

$out = [];

foreach (\Dcrypt\OpensslSupported::algos() as $algo) {
    $out[strtolower($algo)] = base64_encode(\Dcrypt\OpensslStatic::encrypt('hello', 'world', 'aes-256-gcm', $algo, 1));
}

file_put_contents(__DIR__ . '/../tests/vectors/openssl-static-algos.json', \json_encode($out, JSON_PRETTY_PRINT));