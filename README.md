# php-edge-auth

[![Version 1.0.0](https://img.shields.io/badge/version-v1.0.0-green.svg)](:release:)
[![Build Status](https://travis-ci.org/jorge-matricali/php-edge-auth.svg?branch=master)](:status:) [![Coverage Status](https://coveralls.io/repos/github/jorge-matricali/php-edge-auth/badge.svg?branch=master)](https://coveralls.io/github/jorge-matricali/php-edge-auth?branch=master)
[![MIT licensed](https://img.shields.io/github/license/jorge-matricali/php-edge-auth.svg)](https://jorge-matricali.mit-license.org/2017) [![Packagist](https://img.shields.io/packagist/dt/jorge-matricali/php-edge-auth.svg)](https://packagist.org/packages/jorge-matricali/php-edge-auth)

Generates authorization token used by Akamai's Auth Token 2.0. It can be used
in the HTTP Cookie, Query String, and Header.
You can configure it in the Property Manager at https://control.akamai.com.

### Installation
```
composer require jorge-matricali/php-edge-auth
```

### Usage
```php
use Matricali\Security\EdgeAuth\TokenAuth;

$edgeAuth = new TokenAuth('aabbccddeeffgg00112233445566', TokenAuth::ALGORITHM_SHA256);
/* @throws Matricali\Security\EdgeAuth\InvalidArgumentException */
$edgeAuth->setIp($client_ip);
$authUrl = $edgeAuth->generateToken();
```
