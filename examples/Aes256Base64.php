<?php

namespace Dcrypt\Examples;

class Aes256Base64 extends \Dcrypt\OpensslBridge
{
    const CIPHER = 'aes-256-gcm';

    const ALGO = 'sha256';

    /**
     * Cost value of zero because we are using a key.
     *
     * @var int
     */
    const COST = 0;

    /**
     * An example key generated with linux command:  head -c 256 /dev/urandom | base64 --wrap 64
     *
     * DO NOT ACTUALLY USE THIS KEY
     *
     * @var string
     */
    const KEY = '
        QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
        QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
        QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
        QUFBQQ==
    ';

    public static function decrypt(string $data): string
    {
        return parent::decrypt(\base64_decode($data), self::KEY);
    }

    public static function encrypt(string $data): string
    {
        return \base64_encode(parent::encrypt($data, self::KEY));
    }
}