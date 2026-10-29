# Changelog

All notable changes to `ArturRios.Jwt` are recorded in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.4.1] - 2026-10-29

### Changed

- The package's project URL is the documentation site's new address, `https://docs.artur-rios.tech/dotnet-jwt`, since the
  site moved from GitHub Pages.

## [1.4.0] - 2026-10-16

### Added

- ES256 (ECDSA P-256 with SHA-256) beside HS256. `JwtKey.FromEcPrivateKeyPem` reads a P-256 private key from a
  PEM, `JwtKey.FromEcPublicJwk` builds a verification key from a JWK's `x` and `y`, and `ToPublicKey` drops the
  private half. An EC key's `Id` is its RFC 7638 thumbprint (`Thumbprint`), derived and never configured.
- `JwtConfiguration.Algorithm`: `JwtAlgorithms.HS256`, the default, or `JwtAlgorithms.ES256`. An ES256
  configuration signs with the private key `SigningKeyId` names in `Keys`, and its tokens carry that key's
  thumbprint as `kid`.
- `JwksDocument.From(keys)` writes a JSON Web Key Set holding only public halves, refusing a key whose id is not
  its thumbprint, and `JwksDocument.Parse(json)` reads one into verification keys. `Parse` skips entries that
  are not EC P-256 signing keys, whose `kid` is not their thumbprint, or that carry a private part (`d`), since a
  published private part means the key is compromised. It returns each key once, skipping an entry whose id
  repeats an earlier one, and skips an entry it cannot decode, such as one holding a lone surrogate escape
  (`\uD800`). A document that is not a key set throws `FormatException`, and so does the same undecodable text in
  the key set's own member names.
- `JwtKey.Algorithm`, `IsAsymmetric`, `CanSign` and `ToSecurityKey()`.

### Changed

- `JwtConfigurationValidator` holds a configuration to its `Algorithm`: an HS256 one may not hold an EC key, and
  an ES256 one must hold EC keys only, each named by its thumbprint, sign with one that has its private half, and
  leave `Secret` empty. HS256 configurations validate exactly as before.

### Security

- Each key validates its own algorithm only — an EC key ES256, a secret HS256 — whatever the token's `alg` header
  says, so an HS256 token keyed with a published public key, or an unsigned one, is refused.
  `IsTokenValidAsync(token, keys)` throws `ArgumentException` for a key set that mixes the two kinds.

## [1.3.0] - 2026-10-15

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

[Unreleased]: https://github.com/artur-rios/dotnet-jwt/compare/1.4.1...HEAD
[1.4.1]: https://github.com/artur-rios/dotnet-jwt/compare/1.4.0...1.4.1
[1.4.0]: https://github.com/artur-rios/dotnet-jwt/compare/1.3.0...1.4.0
[1.3.0]: https://github.com/artur-rios/dotnet-jwt/compare/1.2.0...1.3.0
[1.2.0]: https://github.com/artur-rios/dotnet-jwt/compare/v1.1.0...1.2.0
[1.1.0]: https://github.com/artur-rios/dotnet-jwt/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/artur-rios/dotnet-jwt/releases/tag/v1.0.0
