<?php declare(strict_types=1);

class OpensslStackTest extends \PHPUnit\Framework\TestCase
{
    public function testAes256StackWithPassword()
    {
        $stack = (new \Dcrypt\OpensslStack('password', 10000))
            ->add('rc4-40', 'md2')
            ->add('bf-cbc', 'sha256')
            ->add('bf-cfb', 'sha256')
            ->add('bf-ecb', 'sha256')
            ->add('bf-ofb', 'sha256')
            ->add('camellia-256-cfb', 'ripemd320')
            ->add('camellia-256-ofb', 'ripemd320')
            ->add('aes-256-cbc', 'sha512')
            ->add('aes-256-ecb', 'sha512')
            ->add('aes-256-cbc', 'sha512')
            ->add('aes-256-ctr', 'sha512')
            ->add('aes-256-cfb', 'sha512')
            ->add('aes-256-ofb', 'sha512')
            ->add('aes-256-gcm', 'sha512');

        $encrypted = $stack->encrypt("a secret");

        $plaintext = $stack->decrypt($encrypted);

        $this->assertEquals("a secret", $plaintext);
    }

    public function testAes256StackWithKeyFromReadmeFile()
    {
        $key = \Dcrypt\OpensslKeyGenerator::newKey();

        $stack = (new \Dcrypt\OpensslStack($key))
            ->add('aes-256-ecb', 'snefru')
            ->add('aes-256-ofb', 'sha224')
            ->add('aes-256-cbc', 'sha256')
            ->add('aes-256-ctr', 'sha384')
            ->add('aes-256-gcm', 'sha512');

        $encrypted = $stack->encrypt("a secret");

        $plaintext = $stack->decrypt($encrypted);

        $this->assertEquals("a secret", $plaintext);
    }
}