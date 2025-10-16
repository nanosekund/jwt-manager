<?php
namespace Nanosekund\JWT;

/**
 * Class for handling JSON Web Tokens (JWT).
 * Supports creating, validating, and decoding tokens using HMAC-SHA256.
 */
class Manager
{
    // Secret key used for signing and verifying tokens
    private $secretKey;
    // Optional expected issuer value for validating 'iss' claim
    private $expectedIssuer;
    // Allowed clock skew (in seconds) when validating time-based claims like exp
    private $leeway = 0;
    // When true, emit debug logs on validation failures
    private $debug = false;
    // Store last structured error (code/message)
    private $lastError = null;
    // Default token lifetime in seconds when creating tokens (used if payload has no exp)
    private $defaultTtl = 3600;

    /**
     * Constructor
     * @param string $secretKey - Secret key for signing
     */
    public function __construct($secretKey, $expectedIssuer = null, $leeway = 0, $debug = false, $defaultTtl = 3600)
    {
        $this->secretKey = $secretKey;
        $this->expectedIssuer = $expectedIssuer;
        $this->leeway = (int)$leeway;
        $this->debug = (bool)$debug;
        $this->defaultTtl = max(0, (int)$defaultTtl);
    }

    /**
     * Enable or disable debug logging for validation failures
     * @param bool $on
     */
    public function setDebug($on)
    {
        $this->debug = (bool)$on;
    }

    /**
     * Check if debug logging is enabled
     * @return bool
     */
    public function isDebug()
    {
        return $this->debug;
    }

    /**
     * Get the last structured error recorded by validateToken
     * @return array|null ['code'=>string, 'message'=>string] or null
     */
    public function getLastError()
    {
        return $this->lastError;
    }

    /**
     * Clear the last recorded error
     */
    public function clearLastError()
    {
        $this->lastError = null;
    }

    /**
     * Internal helper to record failures and optionally return structured responses
     * @param bool $withReason
     * @param string $code
     * @param string $message
     * @return mixed false or array depending on $withReason
     */
    private function fail($withReason, $code, $message)
    {
        $this->lastError = ['code' => $code, 'message' => $message];
        if ($this->debug) {
            error_log(sprintf('JWT validation failed [%s]: %s', $code, $message));
        }
        if ($withReason) {
            return ['valid' => false, 'code' => $code, 'message' => $message];
        }
        return false;
    }

    /**
     * Set allowed leeway in seconds for time-based claim validation (exp, nbf)
     * @param int $seconds
     */
    public function setLeeway($seconds)
    {
        $this->leeway = max(0, (int)$seconds);
    }

    /**
     * Set default TTL (seconds) for tokens created when payload has no exp
     * @param int $seconds
     */
    public function setDefaultTtl($seconds)
    {
        $this->defaultTtl = max(0, (int)$seconds);
    }

    /**
     * Get default TTL in seconds
     * @return int
     */
    public function getDefaultTtl()
    {
        return $this->defaultTtl;
    }

    /**
     * Get currently configured leeway in seconds
     * @return int
     */
    public function getLeeway()
    {
        return $this->leeway;
    }

    /**
     * Set the expected issuer claim value (iss)
     * @param string|null $issuer
     * @return void
     */
    public function setExpectedIssuer($issuer)
    {
        $this->expectedIssuer = $issuer;
    }

    /**
     * Get the currently configured expected issuer
     * @return string|null
     */
    public function getExpectedIssuer()
    {
        return $this->expectedIssuer;
    }

    /**
     * Creates a JWT token from a given payload
     * @param array $payload - Data to include in the token
     * @return string - JWT token in the format header.payload.signature
     */
    public function createToken($payload)
    {
        // Ensure payload is an array
        if (!is_array($payload)) {
            $payload = [];
        }

        // Populate issued-at if missing
        if (!isset($payload['iat'])) {
            $payload['iat'] = time();
        }

        // Populate expiration if missing using default TTL
        if (!isset($payload['exp'])) {
            $payload['exp'] = $payload['iat'] + $this->defaultTtl;
        }

        // Create JWT header and encode it in Base64URL format
        $base64UrlHeader = $this->base64UrlEncode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));

        // Encode the payload in Base64URL format
        $base64UrlPayload = $this->base64UrlEncode(json_encode($payload));

        // Generate the signature using HMAC-SHA256
        $base64UrlSignature = hash_hmac('sha256', $base64UrlHeader . '.' . $base64UrlPayload, $this->secretKey, true);
        $base64UrlSignature = $this->base64UrlEncode($base64UrlSignature);

        // Return the complete JWT token
        return $base64UrlHeader . '.' . $base64UrlPayload . '.' . $base64UrlSignature;
    }

    /**
     * Encodes data to Base64URL format (used in JWT)
     * @param string $data - Data to encode
     * @return string - Base64URL encoded string
     */
    private function base64UrlEncode($data)
    {
        $base64 = base64_encode($data);
        $base64Url = strtr($base64, '+/', '-_'); // Replace characters for URL safety
        return rtrim($base64Url, '='); // Remove padding
    }

    /**
     * Decodes Base64URL encoded data back to a string
     * @param string $data - Base64URL encoded string
     * @return string - Decoded data
     */
    private function base64UrlDecode($data)
    {
        $base64 = strtr($data, '-_', '+/'); // Restore original characters
        $mod4 = strlen($base64) % 4;
        if ($mod4 > 0) {
            $base64 .= str_repeat('=', 4 - $mod4);
        }
        return base64_decode($base64);
    }

    /**
     * Validates a JWT token by checking its signature
     * @param string $token - JWT token to validate
     * @return bool - True if the signature is valid, false otherwise
     */
    /**
     * Validate token. By default returns bool. If $withReason is true, returns structured array:
     * ['valid' => bool, 'code' => string|null, 'message' => string|null]
     * @param string $token
     * @param bool $withReason
     * @return bool|array
     */
    public function validateToken($token, $withReason = false)
    {
        $this->clearLastError();
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return $this->fail($withReason, 'malformed', 'Token does not have 3 parts');
        }
        list($base64UrlHeader, $base64UrlPayload, $base64UrlSignature) = $parts;

        // Decode the signature from the token
        $signature = $this->base64UrlDecode($base64UrlSignature);
        if ($signature === false) {
            return $this->fail($withReason, 'sig_decode_failed', 'Signature part base64 decoding failed');
        }

        // Generate the expected signature
        $expectedSignature = hash_hmac('sha256', $base64UrlHeader . '.' . $base64UrlPayload, $this->secretKey, true);

        // Compare the signatures securely
        if (!hash_equals($signature, $expectedSignature)) {
            return $this->fail($withReason, 'invalid_signature', 'Signature does not match');
        }

        // Optionally validate header (alg)
        $headerJson = $this->base64UrlDecode($base64UrlHeader);
        $header = json_decode($headerJson, true);
        if (!is_array($header) || empty($header['alg']) || strtoupper($header['alg']) !== 'HS256') {
            return $this->fail($withReason, 'invalid_header', 'Invalid or unsupported header/alg');
        }

        // Validate payload 'exp' if present
        $payloadJson = $this->base64UrlDecode($base64UrlPayload);
        if ($payloadJson === false) {
            return $this->fail($withReason, 'payload_decode_failed', 'Payload part base64 decoding failed');
        }
        $payload = json_decode($payloadJson, true);
        if (is_array($payload) && isset($payload['exp']) && is_numeric($payload['exp'])) {
            $expiry = (int)$payload['exp'];
            if (time() > ($expiry + $this->leeway)) {
                return $this->fail($withReason, 'expired', 'Token has expired');
            }
        }

        // Validate 'nbf' (not before) claim if present
        if (is_array($payload) && isset($payload['nbf']) && is_numeric($payload['nbf'])) {
            $notBefore = (int)$payload['nbf'];
            // Allow leeway: token is valid if current time + leeway >= nbf
            if ((time() + $this->leeway) < $notBefore) {
                return $this->fail($withReason, 'not_yet_valid', 'Token is not yet valid (nbf)');
            }
        }

        // Validate 'iat' (issued at) claim if present - reject tokens issued in the future beyond leeway
        if (is_array($payload) && isset($payload['iat']) && is_numeric($payload['iat'])) {
            $issuedAt = (int)$payload['iat'];
            if ($issuedAt > (time() + $this->leeway)) {
                return $this->fail($withReason, 'iat_in_future', 'Token issued-at (iat) is in the future');
            }
        }

        // Validate issuer 'iss' if an expected issuer is configured
        if (!empty($this->expectedIssuer)) {
            if (!is_array($payload) || !isset($payload['iss']) || $payload['iss'] !== $this->expectedIssuer) {
                return $this->fail($withReason, 'invalid_issuer', 'Issuer (iss) does not match expected value');
            }
        }

        if ($withReason) {
            return ['valid' => true, 'code' => null, 'message' => null];
        }
        return true;
    }

    /**
     * Decodes the payload from a JWT token
     * @param string $token - JWT token to decode
     * @return array|null - Payload as a PHP array, or null if invalid
     */
    public function decodeToken($token)
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }
        $base64UrlPayload = $parts[1];

        // Decode and convert to array
        $payloadJson = $this->base64UrlDecode($base64UrlPayload);
        if ($payloadJson === false) {
            return null;
        }
        $payload = json_decode($payloadJson, true);
        return $payload;
    }
}
?>