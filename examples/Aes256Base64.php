<?php

class Aes256Base64 extends \Dcrypt\OpensslBridge
{
    const CIPHER = 'aes-256-cfb';

    const ALGO = 'sha256';

    const COST = 0;

    /**
     * An example key generated with linux command:  head -c 128 /dev/urandom | base64 --wrap 0
     */
    const KEY = 'eXy/tXzysbiAqyLHnXnaFEJoTDl3faDVq148M5ACiavzgeiwXHw2QWDoBvLJ/nUV+hPaCqRzuwWmoxn4RsaA3RnnU0IQnumF4mLkb71d3PV/c7DcpJ935Mhd34uH9xaPmbkmy3ikl6Eakqix020nuHBPvR7RAiYrcZschUGlFYk=';

    public static function decrypt(string $data): string
    {
        $key = base64_decode(self::KEY);

        return parent::decrypt(base64_decode($data), $key);
    }

    public static function encrypt(string $data): string
    {
        $key = base64_decode(self::KEY);

        return base64_encode(parent::encrypt($data, $key));
    }
}