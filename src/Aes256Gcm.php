<?php

declare(strict_types=1);

namespace Dcrypt;

class Aes256Gcm extends OpensslBridge
{
    /**
     * AES-256 cipher identifier that will be passed to openssl.
     *
     * @var string
     */
    const CIPHER = 'aes-256-gcm';

    /**
     * Use SHA3-256 hashing algo to authenticate messages.
     *
     * @var string
     */
    const ALGO = 'sha3-256';
}
