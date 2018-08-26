# php-edge-auth

[![Latest Stable Version](https://poser.pugx.org/jorge-matricali/akamai-token-auth/v/stable)](https://packagist.org/packages/jorge-matricali/akamai-token-auth)
[![Build Status](https://travis-ci.org/jorge-matricali/php-edge-auth.svg?branch=master)](:status:) [![Coverage Status](https://coveralls.io/repos/github/jorge-matricali/php-edge-auth/badge.svg?branch=master)](https://coveralls.io/github/jorge-matricali/php-edge-auth?branch=master)
[![MIT licensed](https://img.shields.io/github/license/jorge-matricali/php-edge-auth.svg)](https://jorge-matricali.mit-license.org/2017)
[![Total Downloads](https://poser.pugx.org/jorge-matricali/akamai-token-auth/downloads)](https://packagist.org/packages/jorge-matricali/akamai-token-auth)
[![Latest Unstable Version](https://poser.pugx.org/jorge-matricali/akamai-token-auth/v/unstable)](https://packagist.org/packages/jorge-matricali/akamai-token-auth)
[![composer.lock](https://poser.pugx.org/jorge-matricali/akamai-token-auth/composerlock)](https://packagist.org/packages/jorge-matricali/akamai-token-auth)

Generates authorization token used by Akamai's Auth Token 2.0. It can be used
in the HTTP Cookie, Query String, and Header.
You can configure it in the Property Manager at https://control.akamai.com.

### Installation
```
composer require jorge-matricali/akamai-token-auth
```

### Usage
```php
use Matricali\Security\EdgeAuth\TokenAuth;

$edgeAuth = new TokenAuth('aabbccddeeffgg00112233445566', TokenAuth::ALGORITHM_SHA256);

/* @throws Matricali\Security\EdgeAuth\InvalidArgumentException */
$edgeAuth->setIp($client_ip);

$authUrl = $edgeAuth->generateToken();
```
