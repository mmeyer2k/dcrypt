<?php

namespace Dcrypt;

class OpensslStack
{
    private $stack = [];

    private $passkey;

    private $cost;

    public function __construct(string $passkey, int $cost = 0)
    {
        $this->passkey = $passkey;

        $this->cost = $cost;

        return $this;
    }

    public function add(string $cipher, string $algo): self
    {
        $this->stack[] = [$cipher, $algo];

        return $this;
    }

    public function encrypt(string $data): string
    {
        foreach ($this->stack as $s) {
            $data = OpensslStatic::encrypt($data, $this->passkey, $s[0], $s[1], $this->cost);
        }

        return $data;
    }

    public function decrypt(string $data): string
    {
        foreach (\array_reverse($this->stack) as $s) {
            $data = OpensslStatic::decrypt($data, $this->passkey, $s[0], $s[1], $this->cost);
        }

        return $data;
    }
}