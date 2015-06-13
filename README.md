# hmac-auth

Simple token authentication for PHP

## Usage

### Require via Composer

`composer require zacharyrankin/hmac-auth`

### Client

```php
use zacharyrankin\hmac_auth\Authenticator;
use zacharyrankin\hmac_auth\Client;

$auth = new Authenticator;
$token = $auth->createToken(new Client('some user', 'user secret'));
header('X-Authorization-Token: ' . $token);
```

### Server

```php
use zacharyrankin\hmac_auth\Authenticator;
use zacharyrankin\hmac_auth\Client;

$auth = new Authenticator
$auth->authenticate(
  $_SERVER['HTTP_X_AUTHORIZATION_TOKEN'],
  function ($clientId) {
    return new Client($clientId, SomeModel::findSecret($clientId));
  },
  300 // expiration in seconds
);
```
