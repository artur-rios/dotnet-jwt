using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace ArturRios.Jwt;

/// <summary>
/// Creates and validates JSON Web Tokens (JWTs) based on a <see cref="JwtConfiguration"/>.
/// </summary>
public class JwtHandler
{
    /// <summary>
    /// The algorithms a token may name in its <c>alg</c> header: the one <see cref="CreateToken"/> signs with.
    /// </summary>
    private static readonly string[] s_validAlgorithms = [SecurityAlgorithms.HmacSha256];

    private readonly JwtSecurityTokenHandler _handler = new();

    /// <summary>
    /// Creates a signed JWT (using HMAC-SHA256) from the given configuration.
    /// </summary>
    /// <remarks>
    /// Signs with the key <see cref="JwtConfiguration.SigningKeyId"/> names, when it names one, and
    /// stamps that identifier on the token's <c>kid</c> header so a validator can tell which key to
    /// check it against. Otherwise signs with <see cref="JwtConfiguration.Secret"/> and writes no
    /// <c>kid</c>, exactly as it did before rotation was supported.
    /// </remarks>
    /// <param name="configuration">The issuer, audience, expiration, signing key and claims to embed in the token.</param>
    /// <returns>The serialized, signed JWT.</returns>
    /// <exception cref="InvalidOperationException">
    /// <see cref="JwtConfiguration.SigningKeyId"/> names a key that is not in
    /// <see cref="JwtConfiguration.Keys"/>. Signing with a key nothing will accept would produce a
    /// token that fails on its first use, so it fails here instead, where the cause is visible.
    /// </exception>
    public string CreateToken(JwtConfiguration configuration)
    {
        var signingKey = ResolveSigningKey(configuration);

        var claimsList = configuration.Claims.Select(c => new Claim(c.Key, c.Value)).ToList();

        ClaimsIdentity identity = new(claimsList);

        var creationDate = DateTime.UtcNow;
        var expirationDate = creationDate + TimeSpan.FromSeconds(configuration.ExpirationInSeconds);

        var token = _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = configuration.Issuer,
            Audience = configuration.Audience,
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256Signature),
            Subject = identity,
            NotBefore = creationDate,
            Expires = expirationDate
        });

        return _handler.WriteToken(token);
    }

    /// <summary>
    /// Reads a JWT and extracts the user id from its "id" claim, without validating the token's signature.
    /// </summary>
    /// <param name="token">The JWT to read.</param>
    /// <returns>
    /// The user id from the token's "id" claim, or <see langword="null"/> when the token cannot be read,
    /// carries no "id" claim, or carries one that is not an integer.
    /// </returns>
    /// <remarks>
    /// The value is unverified: reading a claim proves nothing about who wrote it. Validate the token
    /// first if the id is going to decide anything.
    /// </remarks>
    public int? GetUserIdFromToken(string token)
    {
        if (ReadToken(token) is not JwtSecurityToken jwtToken)
        {
            return null;
        }

        var claim = jwtToken.Claims.FirstOrDefault(x => x.Type == "id");

        return claim is not null && int.TryParse(claim.Value, out var userId) ? userId : null;
    }

    /// <summary>
    /// Reads the <c>kid</c> header naming the key that signed a JWT, without validating its signature.
    /// </summary>
    /// <param name="token">The JWT to read.</param>
    /// <returns>
    /// The key identifier, or <see langword="null"/> if the token cannot be read or carries no
    /// <c>kid</c>.
    /// </returns>
    /// <remarks>
    /// The value is unverified, because reading a header proves nothing about who wrote it. It says
    /// which key to check the signature against and must not be trusted for anything else.
    /// </remarks>
    public string? GetKeyIdFromToken(string token)
    {
        if (ReadToken(token) is not JwtSecurityToken jwtToken)
        {
            return null;
        }

        return string.IsNullOrWhiteSpace(jwtToken.Header.Kid) ? null : jwtToken.Header.Kid;
    }

    /// <summary>
    /// Validates a JWT's signature and lifetime against the given secret.
    /// </summary>
    /// <param name="token">The JWT to validate.</param>
    /// <param name="secret">The secret key expected to have been used to sign the token.</param>
    /// <returns>
    /// <see langword="true"/> if the token is signed with HMAC-SHA256 under <paramref name="secret"/> and has
    /// not expired; otherwise — including when <paramref name="secret"/> is blank — <see langword="false"/>.
    /// </returns>
    /// <remarks>
    /// <para>
    /// The issuer and the audience are <b>not</b> checked. A token signed with the same secret by a
    /// different issuer, or minted for a different audience, passes here. Check those claims yourself
    /// when more than one party holds the secret.
    /// </para>
    /// <para>
    /// Only HMAC-SHA256 (<c>HS256</c>) is accepted, the one algorithm <see cref="CreateToken"/> signs
    /// with. The <c>alg</c> header is chosen by whoever wrote the token, so it is pinned rather than
    /// trusted.
    /// </para>
    /// </remarks>
    public Task<bool> IsTokenValidAsync(string token, string secret) =>
        IsSignatureValidAsync(token, secret);

    /// <summary>
    /// Validates a JWT's signature against any of the given keys, so tokens signed with a key that is
    /// no longer the signing key remain valid until it is withdrawn.
    /// </summary>
    /// <param name="token">The JWT to validate.</param>
    /// <param name="keys">The keys whose signatures are accepted. A key with a blank secret accepts nothing.</param>
    /// <returns><see langword="true"/> if the token's signature is valid and it has not expired; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// <para>
    /// The issuer and the audience are <b>not</b> checked, and only HMAC-SHA256 is accepted, as with
    /// the single-secret overload.
    /// </para>
    /// <para>
    /// A token carrying a <c>kid</c> is checked against that key alone. An unrecognised <c>kid</c> is
    /// refused without trying the others: the identifier came from the token, so an unknown one says
    /// the token was signed by something this configuration does not accept, and trying every key
    /// anyway would only spend work to reach the same answer.
    /// </para>
    /// <para>
    /// A token carrying no <c>kid</c> is tried against each key in turn. That is what lets a
    /// deployment adopt rotation without invalidating the tokens it issued before it did.
    /// </para>
    /// </remarks>
    public async Task<bool> IsTokenValidAsync(string token, IEnumerable<JwtKey> keys)
    {
        var candidates = keys.ToList();

        if (candidates.Count == 0)
        {
            return false;
        }

        if (GetKeyIdFromToken(token) is { } keyId)
        {
            var named = candidates.FirstOrDefault(key => key.Id == keyId);

            return named is not null && await IsSignatureValidAsync(token, named.Secret, named.Id);
        }

        foreach (var key in candidates)
        {
            if (await IsSignatureValidAsync(token, key.Secret, key.Id))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Reads a JWT without validating its signature, returning <see langword="null"/> if it cannot be read.
    /// </summary>
    /// <remarks>
    /// <see cref="JwtSecurityTokenHandler.CanReadToken"/> only checks the shape — three segments separated
    /// by dots — so it says yes to <c>"a.b.c"</c> and the read that follows then throws on the malformed
    /// base64url. Since the token is caller input, and the public readers document a <see langword="null"/>
    /// for anything unreadable, the failure is caught here rather than handed to the caller.
    /// </remarks>
    private SecurityToken? ReadToken(string token)
    {
        if (!_handler.CanReadToken(token))
        {
            return null;
        }

        try
        {
            return _handler.ReadToken(token);
        }
        catch (ArgumentException)
        {
            return null;
        }
        catch (SecurityTokenException)
        {
            return null;
        }
    }

    /// <summary>
    /// The key a configuration signs with: the one <see cref="JwtConfiguration.SigningKeyId"/> names,
    /// or <see cref="JwtConfiguration.Secret"/> when it names none.
    /// </summary>
    private static SymmetricSecurityKey ResolveSigningKey(JwtConfiguration configuration)
    {
        if (string.IsNullOrWhiteSpace(configuration.SigningKeyId))
        {
            return KeyFrom(configuration.Secret);
        }

        var signingKey = configuration.Keys.FirstOrDefault(key => key.Id == configuration.SigningKeyId)
                         ?? throw new InvalidOperationException(
                             $"The signing key id '{configuration.SigningKeyId}' names no key in {nameof(JwtConfiguration.Keys)}.");

        return KeyFrom(signingKey.Secret, signingKey.Id);
    }

    /// <summary>
    /// Builds the signing key, carrying its identifier when it has one so that
    /// <see cref="JwtSecurityTokenHandler"/> writes the <c>kid</c> header.
    /// </summary>
    /// <remarks>
    /// <para>
    /// ASCII rather than UTF-8, matching what this class has always used. Reading a secret's bytes
    /// differently would silently invalidate every token signed with a secret outside ASCII, which is
    /// not a change to make while adding a feature.
    /// </para>
    /// <para>
    /// A consequence worth knowing: <see cref="Encoding.ASCII"/> replaces every character above U+007F
    /// with <c>?</c>, so a secret drawn from a wider alphabet contributes far less entropy than its
    /// length suggests, and two such secrets can collapse onto the same key. Keep secrets to printable
    /// ASCII, and at least 32 bytes of it, which is what HMAC-SHA256 needs.
    /// </para>
    /// </remarks>
    private static SymmetricSecurityKey KeyFrom(string secret, string? keyId = null)
    {
        var bytes = string.IsNullOrWhiteSpace(secret) ? [] : Encoding.ASCII.GetBytes(secret);

        return new SymmetricSecurityKey(bytes) { KeyId = keyId };
    }

    /// <summary>
    /// Checks a token's signature and lifetime against one secret.
    /// </summary>
    /// <remarks>
    /// A blank secret is a refusal, not an error: <see cref="SymmetricSecurityKey"/> throws on a
    /// zero-length key, and the public validators promise a <see langword="false"/> for anything that
    /// does not validate — a missing secret included.
    /// </remarks>
    private async Task<bool> IsSignatureValidAsync(string token, string secret, string? keyId = null)
    {
        if (string.IsNullOrWhiteSpace(secret))
        {
            return false;
        }

        var output = await _handler.ValidateTokenAsync(token,
            new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = KeyFrom(secret, keyId),
                ValidAlgorithms = s_validAlgorithms,
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero
            });

        return output.IsValid;
    }
}
