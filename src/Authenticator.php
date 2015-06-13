<?php

namespace zacharyrankin\hmac_auth;

use UnexpectedValueException;

class Authenticator
{
    /**
     * Holds the version of the authenticator.  This is useful for making sure the signature sent
     * is what the authenticator expects.
     */
    const VERSION = '1';

    /**
     * @param $token
     * @param callable $getClient
     * @param int $expireSeconds
     * @return bool
     * @throws AuthenticationException
     * @throws UnexpectedValueException
     */
    public function authenticate($token, callable $getClient, $expireSeconds = 300)
    {
        $token = explode(':', $token);
        if (count($token) !== 4) {
            throw new AuthenticationException(
                "Invalid token. Must have all 4 expected pieces"
            );
        }

        list($version, $clientId, $timestamp, $signature) = $token;

        if ($version !== self::VERSION) {
            throw new AuthenticationException(
                "Unsupported version. Current version is \"" . self::VERSION . "\", "
                . "you passed \"{$version}\"."
            );
        }

        $client = call_user_func($getClient, $clientId);

        if (!($client instanceof Client)) {
            throw new UnexpectedValueException(
                "Your getClient() callback must return an instance of Client."
            );
        }

        if (!$client->secret) {
            throw new AuthenticationException(
                "Client is missing a secret."
            );
        }

        if (!is_numeric($timestamp)) {
            throw new AuthenticationException(
                "Timestamp invalid. Timestamp must be a valid unix timestamp."
            );
        }

        $currentTime = time();
        if (($currentTime - $timestamp) >= $expireSeconds) {
            throw new AuthenticationException(
                "Timestamp expired.  Provided timestamp "
                . date("Y-m-d H:i:s", $timestamp) . " is not within "
                . "{$expireSeconds} seconds of " . date("Y-m-d H:i:s", $currentTime)
            );
        }

        $verifyAuth = [
            'version'   => self::VERSION,
            'timestamp' => $timestamp,
            'clientId'  => $client->id,
        ];

        if ($signature != $this->getSignature($verifyAuth, $client)) {
            throw new AuthenticationException(
                "Invalid signature.  You should have sent "
                . "`signature = hmac('sha1', '" . $this->getStringForSignature($verifyAuth) . "', "
                . "'your secret')`, your signature was \"" . $signature . "\""
            );
        }

        return true;
    }

    /**
     * @param Client $client
     * @param null $timestamp
     * @return string
     */
    public function createToken(Client $client, $timestamp = null)
    {
        $auth = [
            'version'   => self::VERSION,
            'clientId'  => $client->id,
            'timestamp' => $timestamp ?: time(),
        ];
        $auth['signature'] = $this->getSignature($auth, $client);

        return "{$auth['version']}:{$auth['clientId']}:{$auth['timestamp']}:{$auth['signature']}";
    }

    /**
     * @param array $auth
     * @param Client $client
     * @return string
     */
    private function getSignature(array $auth, Client $client)
    {
        return hash_hmac('sha1', $this->getStringForSignature($auth), $client->secret);
    }

    /**
     * @param array $auth
     * @return string
     */
    private function getStringForSignature(array $auth)
    {
        $authForSort = $auth;
        ksort($authForSort);

        return http_build_query($authForSort);
    }
}
