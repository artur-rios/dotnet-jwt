# Dotnet JWT

[![Docs](https://img.shields.io/badge/docs-website-blue)](https://artur-rios.github.io/dotnet-jwt)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)
[![NuGet](https://img.shields.io/nuget/v/ArturRios.Jwt.svg)](https://www.nuget.org/packages/ArturRios.Jwt)

Provides a clean, minimal API for creating, validating and reading JSON Web Tokens (JWT) in .NET.

## Requirements

- .NET 10.0 or later

## Installation

```bash
dotnet add package ArturRios.Jwt
```

## Features

- Create signed JWTs (HMAC-SHA256) from a `JwtConfiguration`
- Validate a JWT's signature against a secret, or against a set of keys
- Rotate signing keys without invalidating the tokens already issued
- Read the user id from a token's `id` claim, and the `kid` naming the key that signed it
- Validate a `JwtConfiguration` with [FluentValidation](https://docs.fluentvalidation.net) rules before using it

## Usage

### Configuring

```csharp
using ArturRios.Jwt;

var configuration = new JwtConfiguration(
    expirationInSeconds: 3600,
    issuer: "my-api",
    audience: "my-app",
    secret: "a-secret-key-that-is-at-least-32-bytes-long",
    claims: new Dictionary<string, string> { { "id", "42" } }
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
    expirationInSeconds: 3600,
    issuer: "my-api",
    audience: "my-app",
    secret: string.Empty,
    claims: new Dictionary<string, string> { { "id", "42" } }
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
> `Secret` is unused; without them, everything behaves exactly as it did before this existed.

### Reading the user id from a token

```csharp
var userId = handler.GetUserIdFromToken(token);
var keyId = handler.GetKeyIdFromToken(token);
```

> Note: tokens are signed with HMAC-SHA256, which requires a secret of at least 32 bytes (256 bits).

## Versioning

Semantic Versioning (SemVer). Breaking changes result in a new major version. New methods or non-breaking behavior
changes increment the minor version; fixes or tweaks increment the patch.

## Build, test and publish

Use the official [.NET CLI](https://learn.microsoft.com/en-us/dotnet/core/tools/) to build, test and publish the project and Git for source control.
If you want, optional helper toolsets I built to facilitate these tasks are available:

- [Dotnet Tools](https://github.com/artur-rios/dotnet-tools)
- [Python Dotnet Tools](https://github.com/artur-rios/python-dotnet-tools)

## Legal Details

This project is licensed under the [MIT License](https://en.wikipedia.org/wiki/MIT_License). A copy of the license is available at [LICENSE](./LICENSE) in the repository.
