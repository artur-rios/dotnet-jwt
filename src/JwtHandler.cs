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
    private readonly JwtSecurityTokenHandler _handler = new();

    /// <summary>
    /// Creates a signed JWT (using HMAC-SHA256) from the given configuration.
    /// </summary>
    /// <param name="configuration">The issuer, audience, expiration, signing secret and claims to embed in the token.</param>
    /// <returns>The serialized, signed JWT.</returns>
    public string CreateToken(JwtConfiguration configuration)
    {
        var key = string.IsNullOrWhiteSpace(configuration.Secret) ? [] : Encoding.ASCII.GetBytes(configuration.Secret);

        var claimsList = configuration.Claims.Select(c => new Claim(c.Key, c.Value)).ToList();

        ClaimsIdentity identity = new(claimsList);

        var creationDate = DateTime.Now;
        var expirationDate = creationDate + TimeSpan.FromSeconds(configuration.ExpirationInSeconds);

        JwtSecurityTokenHandler handler = new();

        var token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = configuration.Issuer,
            Audience = configuration.Audience,
            SigningCredentials =
                new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
            Subject = identity,
            NotBefore = creationDate,
            Expires = expirationDate
        });

        return handler.WriteToken(token);
    }

    /// <summary>
    /// Reads a JWT and extracts the user id from its "id" claim, without validating the token's signature.
    /// </summary>
    /// <param name="token">The JWT to read.</param>
    /// <returns>The user id from the token's "id" claim, or <see langword="null"/> if the token cannot be read.</returns>
    public int? GetUserIdFromToken(string token)
    {
        if (ReadToken(token) is not JwtSecurityToken jwtToken)
        {
            return null;
        }

        return int.Parse(jwtToken.Claims.First(x => x.Type == "id").Value);
    }

    /// <summary>
    /// Validates a JWT's signature against the given secret.
    /// </summary>
    /// <param name="token">The JWT to validate.</param>
    /// <param name="secret">The secret key expected to have been used to sign the token.</param>
    /// <returns><see langword="true"/> if the token's signature is valid; otherwise, <see langword="false"/>.</returns>
    public async Task<bool> IsTokenValidAsync(string token, string secret)
    {
        var key = string.IsNullOrWhiteSpace(secret) ? [] : Encoding.ASCII.GetBytes(secret);

        var output = await _handler.ValidateTokenAsync(token,
            new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero
            });

        return output.IsValid;
    }

    /// <summary>
    /// Reads a JWT without validating its signature, returning <see langword="null"/> if it cannot be read.
    /// </summary>
    private SecurityToken? ReadToken(string token)
    {
        return _handler.CanReadToken(token) ? _handler.ReadToken(token) : null;
    }
}
