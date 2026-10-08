# Changelog

All notable changes to `ArturRios.Jwt` are recorded in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `JwtConfigurationValidator` rejects every configuration `CreateToken` cannot sign with, or whose tokens the
  configured keys would not accept: a signing `Secret` (one used because no `SigningKeyId` is set) is required even
  when `Keys` is set, must be at least 32 bytes, and must be the secret of one of the `Keys` when there are any; and
  every key in `Keys` must have a secret of at least 32 bytes. Each of these configurations used to pass validation
  and then throw in `CreateToken`, or issue tokens that failed validation against `Keys`.

### Fixed

- `IsTokenValidAsync` returns `false` for a blank secret, and the key-set overload treats a key with a blank secret
  as accepting nothing, instead of both throwing `ArgumentException` from `SymmetricSecurityKey`.

### Security

- `IsTokenValidAsync` accepts only `HS256` signatures, the one algorithm `CreateToken` uses, instead of any HMAC
  algorithm the token's `alg` header names.

## [1.2.0] - 2026-08-24

### Changed

- `GetUserIdFromToken` and `GetKeyIdFromToken` return `null` for input they cannot read — a token with no `id` claim,
  a non-integer `id`, or a token whose segments are not valid base64url — instead of throwing, as they always
  documented.
- `CreateToken` stamps `nbf` and `exp` from UTC rather than local time.
- `System.IdentityModel.Tokens.Jwt` updated from 8.19.1 to 8.22.0.

### Fixed

- `CreateToken` no longer builds a second `JwtSecurityTokenHandler` on every call.

## [1.1.0] - 2026-08-17

### Added

- Signing key rotation: `JwtConfiguration.Keys` and `SigningKeyId` let one key sign while several are accepted.
  Tokens carry the signing key's id in their `kid` header.
- `JwtHandler.IsTokenValidAsync(token, keys)` validates a token against a set of keys.
- `JwtHandler.GetKeyIdFromToken` reads the `kid` that names a token's signing key.

### Changed

- `JwtConfiguration.Secret` is required only when no `Keys` are configured.

## [1.0.0] - 2026-07-02

### Added

- `JwtConfiguration`, and `JwtConfigurationValidator` to check it with FluentValidation.
- `JwtHandler` to create HMAC-SHA256 signed tokens, validate them against a secret, and read the user id from a
  token's `id` claim.

[Unreleased]: https://github.com/artur-rios/dotnet-jwt/compare/1.2.0...HEAD
[1.2.0]: https://github.com/artur-rios/dotnet-jwt/compare/v1.1.0...1.2.0
[1.1.0]: https://github.com/artur-rios/dotnet-jwt/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/artur-rios/dotnet-jwt/releases/tag/v1.0.0
