# Testing Dcrypt

## Vector testing
To ensure that backwards compatibility is maintained across versions, dcrypt tests new code against old encrypted data.
Vectors are stored in [tests/vectors](https://github.com/mmeyer2k/dcrypt/tree/master/tests/vectors)

## Unit testing
Continuous unit testing on all supported PHP versions is performed using circle-ci with phpunit.

## Mutation testing
Mutation tests performed with [infection/infection](https://github.com/infection/infection).