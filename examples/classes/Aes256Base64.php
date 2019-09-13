<?php

declare(strict_types=1);

namespace Dcrypt\Examples;

class Aes256Base64 extends \Dcrypt\Aes256Gcm
{
    public static function decrypt(string $data, string $key): string
    {
        return parent::decrypt(\base64_decode($data), $key);
    }

    public static function encrypt(string $data, string $key): string
    {
        return \base64_encode(parent::encrypt($data, $key));
    }
}
