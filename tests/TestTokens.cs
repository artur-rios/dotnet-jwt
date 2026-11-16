using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace ArturRios.Jwt.Tests;

/// <summary>
/// Tokens written directly with <see cref="JwtSecurityTokenHandler"/>, so a test can choose a lifetime that
/// <see cref="JwtHandler.CreateToken"/>, which always starts it now, cannot: one that has already ended or has not
/// begun yet. That is how the expiry tests run without waiting for a token to expire.
/// </summary>
internal static class TestTokens
{
    /// <summary>An HS256 token signed with <paramref name="secret"/>, naming <paramref name="keyId"/> when given.</summary>
    /// <param name="secret">The secret to sign with.</param>
    /// <param name="notBefore">The start of the token's lifetime (<c>nbf</c>).</param>
    /// <param name="expires">The end of its lifetime (<c>exp</c>), or <see langword="null"/> for a token with no expiry.</param>
    /// <param name="keyId">The <c>kid</c> header, or <see langword="null"/> for none.</param>
    public static string Hs256(string secret, DateTime notBefore, DateTime? expires, string? keyId = null) =>
        Write(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret)) { KeyId = keyId },
            SecurityAlgorithms.HmacSha256, notBefore, expires);

    /// <summary>An ES256 token signed with <paramref name="key"/>'s private half, naming it by its thumbprint.</summary>
    public static string Es256(JwtKey key, DateTime notBefore, DateTime expires) =>
        Write(key.ToSecurityKey(), SecurityAlgorithms.EcdsaSha256, notBefore, expires);

    /// <summary>A lifetime that ended <paramref name="ago"/> before now, after an hour.</summary>
    public static (DateTime NotBefore, DateTime Expires) EndedAgo(TimeSpan ago)
    {
        var expires = DateTime.UtcNow - ago;

        return (expires.AddHours(-1), expires);
    }

    private static string Write(SecurityKey key, string algorithm, DateTime notBefore, DateTime? expires)
    {
        // Without this, a descriptor with no Expires gets a default of an hour from now.
        var handler = new JwtSecurityTokenHandler { SetDefaultTimesOnTokenCreation = false };

        return handler.WriteToken(handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "issuer",
            Audience = "audience",
            Subject = new ClaimsIdentity([new Claim("id", "1")]),
            NotBefore = notBefore,
            Expires = expires,
            SigningCredentials = new SigningCredentials(key, algorithm)
        }));
    }
}
