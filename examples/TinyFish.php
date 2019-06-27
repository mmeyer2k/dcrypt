<?php

/**
 * A basic example of how to extend dcrypt by overloading the OpensslBridge class.
 *
 * TinyFish uses blowfish64 + crc32 to create small output sizes.
 *
 * This is useful for medium security situations where minimal space consumption is important.
 */
class TinyFish extends \Dcrypt\OpensslBridge
{
    /**
     * Specify using blowfish ofb cipher method
     *
     * @var string
     */
    const CIPHER = 'bf-ofb';

    /**
     * Use crc32 hashing algo to authenticate messages
     *
     * @var string
     */
    const ALGO = 'crc32';

    /**
     * Cost value for hash_pbkdf2
     *
     * @var string
     */
    const COST = 1000;
}