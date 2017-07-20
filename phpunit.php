<?php

require __DIR__ . '/vendor/autoload.php';

// backward compatibility
if (!class_exists('\PHPUnit\Framework\TestCase')) {
    class_alias('\PHPUnit_Framework_TestCase', 'PHPUnit\Framework\TestCase');
}

date_default_timezone_set('UTC');
