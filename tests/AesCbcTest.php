<?php

class AesCbcTest extends AesBase
{
    public static $vectors = [
        'TBKxhZZceWusumsstOpaBV+RA26sb9S5CXF5bMM16fZ4fuJG0JU8wHBTcwRyX/8fu2ILrsKVfxbzuUeHRQ6GX6ad1ZI=',
        'oNINffRHwsdox/XPs8HOGo1FvQx+0YylEmgYyQsQMCdm8TgeGC3b+D2uJKBxoBI2Z82/rn3PAgBhsbdeMYX/26z2nA0=',
        'Dd8n0dRlRap79mkRBQVDwnHVhD3AdME19mSiRIiwgtgMfqXEiGjzCP2HU8F0weTLFTJlW2h1KyGQ6kjmu2Xm2s13Tx4=',
    ];


    public static $class = '\\Dcrypt\\AesCbc';
}
