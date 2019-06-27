<?php

class Aes256Base64 extends \Dcrypt\OpensslBridge
{
    const CIPHER = 'aes-256-cfb';

    const ALGO = 'sha256';

    /**
     * Cost value of zero because we are using a key.
     *
     * @var int
     */
    const COST = 0;

    /**
     * An example key generated with linux command:  head -c 256 /dev/urandom | base64 --wrap 64
     * DONT ACTUALLY USE THIS KEY
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
        $key = \base64_decode(self::KEY);

        return parent::decrypt(\base64_decode($data), $key);
    }

    public static function encrypt(string $data): string
    {
        $key = \base64_decode(self::KEY);

        return \base64_encode(parent::encrypt($data, $key));
    }
}