<?php
namespace zacharyrankin\hmac_auth\tests;

use PHPUnit_Framework_TestCase;
use zacharyrankin\hmac_auth\Authenticator;
use zacharyrankin\hmac_auth\Client;

class AuthenticatorTest extends PHPUnit_Framework_TestCase
{
    public function testTokenCreation()
    {
        $auth = new Authenticator();
        $now = time();
        $client = new Client('stannis', 'secret');
        $token = $auth->createToken($client, $now);
        $this->assertNotEmpty($token);
        $tokenPieces = explode(':', $token);

        $this->assertCount(4, $tokenPieces);
        $this->assertEquals(1, $tokenPieces[0], "Auth version should be first piece of the token");
        $this->assertEquals($client->id, $tokenPieces[1], "Client id should be the 2nd piece of the token");
        $this->assertEquals($now, $tokenPieces[2], "Timestamp should be the 3rd piece of the token");
        $this->assertEquals(
            40,
            strlen($tokenPieces[3]),
            "Signature should be the 4th piece of the token and a SHA1 hash"
        );
    }

    public function testAuthenticationWorks()
    {
        $auth = new Authenticator();
        $client = new Client('stannis', 'secret');
        $token = $auth->createToken($client);
        $this->assertTrue(
            $auth->authenticate($token, function ($clientId) use ($client) {
                $this->assertEquals($client->id, $clientId);
                return $client;
            })
        );
    }

    public function testVersionMatches()
    {
        $this->setExpectedExceptionRegExp(
            'zacharyrankin\hmac_auth\AuthenticationException',
            "/version/"
        );
        $time = time();
        $auth = new Authenticator();
        $auth->authenticate(
            "2:stannis:{$time}:1234567890123456789012345678901234567890",
            function ($clientId) {
                return new Client($clientId, 'secret');
            }
        );
    }

    public function testGetClientCallbackValidation()
    {
        $this->setExpectedExceptionRegExp(
            'UnexpectedValueException',
            "/callback/"
        );
        $time = time();
        $auth = new Authenticator();
        $auth->authenticate(
            "1:stannis:{$time}:1234567890123456789012345678901234567890",
            function ($clientId) {
                return false;
            }
        );
    }

    public function testClientHasValidSecret()
    {
        $this->setExpectedExceptionRegExp(
            'zacharyrankin\hmac_auth\AuthenticationException',
            "/secret/"
        );
        $time = time();
        $auth = new Authenticator();
        $auth->authenticate(
            "1:stannis:{$time}:1234567890123456789012345678901234567890",
            function ($clientId) {
                return new Client('stannis', '');
            }
        );
    }

    public function testTimestampGetsValidated()
    {
        $this->setExpectedExceptionRegExp(
            'zacharyrankin\hmac_auth\AuthenticationException',
            "/Timestamp invalid/"
        );
        $auth = new Authenticator();
        $auth->authenticate(
            "1:stannis:aasd:1234567890123456789012345678901234567890",
            function ($clientId) {
                return new Client('stannis', 'secret');
            }
        );
    }

    public function testExpiration()
    {
        $this->setExpectedExceptionRegExp(
            'zacharyrankin\hmac_auth\AuthenticationException',
            "/Timestamp expired/"
        );
        $auth = new Authenticator();
        $auth->authenticate(
            "1:stannis:0:1234567890123456789012345678901234567890",
            function ($clientId) {
                return new Client('stannis', 'secret');
            }
        );
    }

    public function testSignatureValidated()
    {
        $this->setExpectedExceptionRegExp(
            'zacharyrankin\hmac_auth\AuthenticationException',
            "/Invalid signature/"
        );
        $time = time();
        $auth = new Authenticator();
        $auth->authenticate(
            "1:stannis:{$time}:",
            function ($clientId) {
                return new Client('stannis', 'secret');
            }
        );
    }
}
