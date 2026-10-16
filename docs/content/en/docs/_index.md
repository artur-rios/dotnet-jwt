---
title: Documentation
linkTitle: Documentation
weight: 20
description: >-
  Provides a clean, minimal API for creating, validating and reading JSON Web Tokens (JWT) in .NET.
---

Provides a clean, minimal API for creating, validating and reading JSON Web Tokens (JWT) in .NET.

## Requirements

- .NET 10.0 or later

## Installation

```bash
dotnet add package ArturRios.Jwt
```

## Features

- Create signed JWTs from a `JwtConfiguration`, with HMAC-SHA256 (a shared secret) or ES256 (an EC P-256 private key)
- Validate a JWT's signature against a secret, or against a set of keys, each key accepting its own algorithm only
- Rotate signing keys without invalidating the tokens already issued
- Publish ES256 public keys as a JSON Web Key Set, and read one to validate another issuer's tokens
- Read the user id from a token's `id` claim, and the `kid` naming the key that signed it
- Validate a `JwtConfiguration` with [FluentValidation](https://docs.fluentvalidation.net) rules before using it

## Usage

### Configuring

```csharp
using ArturRios.Jwt;

var configuration = new JwtConfiguration(
    ExpirationInSeconds: 3600,
    Issuer: "my-api",
    Audience: "my-app",
    Secret: "a-secret-key-that-is-at-least-32-bytes-long",
    Claims: new Dictionary<string, string> { { "id", "42" } }
);
```

### Validating the configuration

```csharp
var validator = new JwtConfigurationValidator();
var result = validator.Validate(configuration);

if (!result.IsValid)
{
    // inspect result.Errors
}
```

### Creating a token

```csharp
var handler = new JwtHandler();
var token = handler.CreateToken(configuration);
```

### Validating a token

```csharp
var isValid = await handler.IsTokenValidAsync(token, configuration.Secret);
```

### Rotating the signing key

Replacing a secret outright is a cutover: every token in flight becomes invalid the moment the new
one takes effect. Supplying `Keys` instead makes it a rotation — one key signs, several are accepted.

```csharp
var configuration = new JwtConfiguration(
    ExpirationInSeconds: 3600,
    Issuer: "my-api",
    Audience: "my-app",
    Secret: string.Empty,
    Claims: new Dictionary<string, string> { { "id", "42" } }
)
{
    Keys = [new JwtKey("2026-08", previousSecret), new JwtKey("2026-09", currentSecret)],
    SigningKeyId = "2026-09"
};

var isValid = await handler.IsTokenValidAsync(token, configuration.Keys);
```

Tokens are stamped with the signing key's id in their `kid` header, and `IsTokenValidAsync` checks a
token against the key it names. Rotate in three steps:

1. Add the new key to `Keys` on every instance, leaving `SigningKeyId` alone. Nothing changes yet —
   the new key is merely accepted.
2. Point `SigningKeyId` at the new key. New tokens are signed with it; the ones already issued still
   validate against the old one.
3. Once no token signed with the old key can still be alive — one `ExpirationInSeconds` later — drop
   it from `Keys`.

Step 3 is what completes the rotation, and doing it earlier is exactly what you want when a key has
leaked rather than merely aged: withdrawing a key invalidates its tokens immediately.

A token whose `kid` names a key that is not in `Keys` is refused without trying the others, and a
token carrying no `kid` at all — one issued before you adopted rotation — is tried against every key,
so turning this on does not sign anyone out. The `kid` selects a key and grants nothing: the
signature still decides.

> Note: `Secret` and `Keys` are alternatives. With `Keys` set and `SigningKeyId` naming one of them,
> `Secret` is unused; without them, everything behaves exactly as it did before this existed. With `Keys`
> set but no `SigningKeyId`, tokens are still signed with `Secret` and carry no `kid`, so `Secret` must also
> be one of the `Keys` — otherwise nothing validating against `Keys` accepts them. `JwtConfigurationValidator`
> enforces this.

### Signing with ES256

With HS256, every service that validates your tokens holds the secret that signs them, so any of them
can mint a token the others accept. ES256 splits the key: a private key signs, and its public half,
which you can publish, validates.

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out signing-key.pem
```

```csharp
var signingKey = JwtKey.FromEcPrivateKeyPem(File.ReadAllText("signing-key.pem"));

var configuration = new JwtConfiguration(
    ExpirationInSeconds: 3600,
    Issuer: "my-api",
    Audience: "my-app",
    Secret: string.Empty,
    Claims: new Dictionary<string, string> { { "id", "42" } }
)
{
    Algorithm = JwtAlgorithms.ES256,
    Keys = [signingKey],
    SigningKeyId = signingKey.Id
};

var token = handler.CreateToken(configuration);
var isValid = await handler.IsTokenValidAsync(token, [signingKey.ToPublicKey()]);
```

An ES256 key's `Id` is its [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) thumbprint, so it is
derived from the key and never configured; tokens carry it as their `kid`. Rotation works as with
secrets: sign with the new key, keep the old one's public half in `Keys` (`oldKey.ToPublicKey()`) for
one token lifetime, then drop it.

Each configuration pins one algorithm, and each key validates its own algorithm only — a secret
HS256, an EC key ES256 — whatever a token's `alg` header says. An HS256 token keyed with your public
key is therefore refused, and so is a key set that mixes both kinds of key (`IsTokenValidAsync` throws
`ArgumentException` for one).

### Publishing and reading the public keys (JWKS)

```csharp
// The issuer, e.g. behind GET /.well-known/jwks.json
var json = JwksDocument.From(configuration.Keys.Select(key => key.ToPublicKey()));

// A service validating that issuer's tokens
var keys = JwksDocument.Parse(json);
var isValid = await handler.IsTokenValidAsync(token, keys);
```

`From` writes public halves only and refuses an HS256 secret. `Parse` reads EC P-256 signing keys and
skips any entry it cannot use safely: one that is not an EC P-256 signing key, whose `kid` is not its
thumbprint, or that carries a private part (`d`) — a published private part means the key is
compromised, so it is never trusted. It returns each key once, skipping an entry whose id repeats an
earlier one, and skips an entry it cannot decode, such as one with invalid escapes. A document that is
not a key set (not JSON, or not an object with a `keys` array) throws `FormatException`. Cache the
parsed keys, and fetch the set again — at most once a minute — when a token names a `kid` you do not
know. `JwtKey.ToSecurityKey()` gives Microsoft.IdentityModel's form of a key, for validators that use it
directly; pair each key with its own `Algorithm` only.

### Reading the user id from a token

```csharp
var userId = handler.GetUserIdFromToken(token);
var keyId = handler.GetKeyIdFromToken(token);
```

`GetUserIdFromToken` and `GetKeyIdFromToken` read the token without validating it, and return `null`
for anything they cannot read — an empty string, a token that is not one, a well-shaped token whose
segments are not valid base64url, a token with no `id` claim, or an `id` that is not an integer. The
values they return are unverified: validate the token first if either is going to decide anything.

> Note: tokens are signed with HMAC-SHA256, which requires a secret of at least **32 bytes** (256 bits);
> `JwtConfigurationValidator` rejects a shorter signing secret or key.
> Secrets are read as **ASCII**, and `Encoding.ASCII` replaces every character above U+007F with `?`, so a
> secret drawn from a wider alphabet contributes far less entropy than its length suggests. Keep secrets
> to printable ASCII.

> Note: `IsTokenValidAsync` checks the **signature and the expiry**. It does not check the issuer or the
> audience, so a token signed with the same secret by a different issuer, or minted for a different
> audience, passes. Check those claims yourself when more than one party holds the secret. Only `HS256`
> signatures are accepted, whatever algorithm the token's header names, and a blank secret (or key)
> accepts nothing: the method returns `false` rather than throwing.

## Legal Details

This project is licensed under the [Artur Rios Attribution License](https://github.com/artur-rios/dotnet-jwt/blob/main/LICENSE). It is free and open source: you may view, use, fork, modify, and extend it, provided you credit the author, Artur Rios, with a link to [artur-rios.tech](https://artur-rios.tech) or [github.com/artur-rios](https://github.com/artur-rios).
