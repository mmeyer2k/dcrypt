<?php

declare(strict_types=1);

namespace Dcrypt;

class Aes256Ctr extends Aes256Gcm
{
    /**
     * AES-256 cipher identifier that will be passed to openssl.
     *
     * @var string
     */
    const CIPHER = 'aes-256-ctr';
}
