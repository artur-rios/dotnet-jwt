using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace ArturRios.Jwt.Tests;

/// <summary>
/// Tokens written directly with <see cref="JwtSecurityTokenHandler"/>, as another issuer would write them, so a test
/// can choose a lifetime that <see cref="JwtHandler.CreateToken"/>, which always starts it at its clock's now, cannot:
/// one that has not begun yet, or none at all. A test that needs a token to expire issues it with a
/// <c>FakeTimeProvider</c> and advances the clock instead.
/// </summary>
internal static class TestTokens
{
    /// <summary>An HS256 token signed with <paramref name="secret"/>, naming <paramref name="keyId"/> when given.</summary>
    /// <param name="secret">The secret to sign with.</param>
    /// <param name="notBefore">The start of the token's lifetime (<c>nbf</c>), or <see langword="null"/> for a token with no start.</param>
    /// <param name="expires">The end of its lifetime (<c>exp</c>), or <see langword="null"/> for a token with no expiry.</param>
    /// <param name="keyId">The <c>kid</c> header, or <see langword="null"/> for none.</param>
    public static string Hs256(string secret, DateTime? notBefore, DateTime? expires, string? keyId = null) =>
        Write(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret)) { KeyId = keyId },
            SecurityAlgorithms.HmacSha256, notBefore, expires);

    /// <summary>
    /// An HS256 token whose <c>nbf</c> and <c>exp</c> are written as given, in any order: the token classes refuse to
    /// build a lifetime that ends before it starts, so the payload is written by hand.
    /// </summary>
    public static string Hs256WithRawLifetime(string secret, DateTime notBefore, DateTime expires)
    {
        var credentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret)),
            SecurityAlgorithms.HmacSha256);
        var payload = new JwtPayload
        {
            ["id"] = "1",
            ["nbf"] = EpochTime.GetIntDate(notBefore),
            ["exp"] = EpochTime.GetIntDate(expires)
        };

        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(new JwtHeader(credentials), payload));
    }

    private static string Write(SecurityKey key, string algorithm, DateTime? notBefore, DateTime? expires)
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
