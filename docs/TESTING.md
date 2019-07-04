# Testing Dcrypt

Testing is an essential element of building trust in a library.
Dcrypt tests code in many different ways to ensure high quality and reliability.

## Vector testing

To ensure that backwards compatibility is maintained across versions, dcrypt tests functional output against the output of older versions.
Test vectors are stored in [tests/vectors](https://github.com/mmeyer2k/dcrypt/tree/master/tests/.vectors.json)

## Unit testing

Continuous unit testing on all supported PHP versions is performed using circle-ci with phpunit.

## Mutation testing

Mutation tests performed with [infection/infection](https://github.com/infection/infection).

## Static testing

Sniffing the code with [@squizlabs/PHP_CodeSniffer](https://github.com/squizlabs/PHP_CodeSniffer) is now part of the build requirements.
