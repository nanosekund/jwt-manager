# JWT Manager

Lightweight PHP JWT helper for creating and validating JSON Web Tokens (HS256).

This file contains a compact `Manager` class that implements common JWT operations without external dependencies. It's intended for small projects or learning purposes.

## Features

- Create JWTs (HS256)
- Validate signature, `exp`, `nbf`, optional `iat`, and optional `iss`
- Configurable leeway (clock skew tolerance)
- Optional debug logging and structured validation failure reasons
- Default TTL when creating tokens (auto-populates `iat`/`exp`)

## Quick usage

```php
require_once __DIR__ . '/class.jwtmanager.php';
use Nanosekund\JWT\Manager as JwtManager;

$secret = 'your-very-secret-key';
$issuer = 'Your Service Name';
// new Manager(secret, expectedIssuer=null, leewaySeconds=0, debug=false, defaultTtl=3600)
$mgr = new JwtManager($secret, $issuer, 60, true, 3600);

// Create a token (payload may include custom claims; iat/exp are added if missing)
$payload = ['sub' => 123, 'role' => 'user'];
$token = $mgr->createToken($payload);

// Validate token (boolean)
if ($mgr->validateToken($token)) {
    // valid
} else {
    // invalid; get last error (structured)
    $err = $mgr->getLastError();
}

// Validate token with reason (structured return)
$result = $mgr->validateToken($token, true);
if ($result['valid']) {
    // ok
} else {
    echo "Validation failed: {$result['code']} - {$result['message']}";
}

// Decode payload
$payload = $mgr->decodeToken($token);
```

## Constructor and configuration

Constructor signature in the class:

```php
public function __construct($secretKey, $expectedIssuer = null, $leeway = 0, $debug = false, $defaultTtl = 3600)
```

- `$secretKey` (string) — HMAC secret used for HS256 signing/verification.
- `$expectedIssuer` (string|null) — optional `iss` claim to validate against.
- `$leeway` (int) — allowed clock skew (seconds) when checking `exp`/`nbf` (recommended small value like 30–120).
- `$debug` (bool) — when true, validation failures are logged with `error_log`.
- `$defaultTtl` (int) — default token lifetime (seconds) used by `createToken()` when payload lacks `exp`.

You can also configure at runtime via setters:

- `setLeeway(int $seconds)`
- `setDefaultTtl(int $seconds)`
- `setExpectedIssuer(string $issuer)`
- `setDebug(bool $on)`
- `getLastError()` — returns last structured error as `['code'=>..., 'message'=>...]`

## Validation behavior

- `validateToken($token)` — default boolean return (true/false).
- `validateToken($token, true)` — returns structured result `['valid'=>bool, 'code'=>string|null, 'message'=>string|null]`.
- The validation order is:
  1. Token structure and signature (HMAC-SHA256) — always verified first.
  2. Header alg check (must be HS256).
  3. Payload decoding.
  4. `exp` check (now > exp + leeway → expired).
  5. `nbf` check (now + leeway < nbf → not yet valid).
  6. `iat` check (optional — historically this class may make it opt-in; consult your installed version) — rejects tokens with `iat` > now + leeway when enforced.
  7. `iss` check (if `expectedIssuer` is set).

On failure the method records a structured error code and message. When debug is enabled, failures are also logged via `error_log`.

## Claims handling in `createToken()`

- If the supplied payload doesn't include `iat`, `createToken()` sets `iat` to current time.
- If the payload doesn't include `exp`, `createToken()` sets `exp = iat + defaultTtl`.
- If you provide your own `iat` or `exp`, they will be preserved.

## Error codes

Some example structured failure codes returned by validation:

- `malformed` — token does not have 3 parts
- `sig_decode_failed` — signature part base64 decode failed
- `invalid_signature` — signature mismatch
- `invalid_header` — header missing or alg not HS256
- `payload_decode_failed` — payload base64 decode failed
- `expired` — token expired
- `not_yet_valid` — token's `nbf` is in the future
- `iat_in_future` — token's `iat` is in the future (if enforced)
- `invalid_issuer` — `iss` claim doesn't match configured issuer

## decodeToken() optional parameter

`decodeToken($token, $asStdClass = false)` now accepts an optional second parameter. By default it returns the payload as an associative array. If you prefer object-style access, pass `true` to receive a `stdClass` object:

```php
$payloadArray = $mgr->decodeToken($token);           // associative array (default)
$payloadObject = $mgr->decodeToken($token, true);    // stdClass object: $payloadObject->sub
```