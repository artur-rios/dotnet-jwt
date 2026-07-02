+++
title = "Dotnet JWT"
+++

# Documentation

Provides a clean, minimal API for creating, validating and reading JSON Web Tokens (JWT) in .NET.

## Requirements

- .NET 10.0 or later

## Installation

```bash
dotnet add package ArturRios.Jwt
```

## Features

- Create signed JWTs (HMAC-SHA256) from a `JwtConfiguration`
- Validate a JWT's signature against a secret
- Read the user id from a token's `id` claim
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

### Reading the user id from a token

```csharp
var userId = handler.GetUserIdFromToken(token);
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

This project is licensed under the [MIT License](https://en.wikipedia.org/wiki/MIT_License). A copy of the license is available at [LICENSE](https://github.com/artur-rios/dotnet-jwt/blob/main/LICENSE) in the repository.
