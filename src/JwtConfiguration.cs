namespace ArturRios.Jwt;

/// <summary>
/// Configuration used to create and validate JSON Web Tokens.
/// </summary>
/// <param name="ExpirationInSeconds">The number of seconds after creation for which the token remains valid.</param>
/// <param name="Issuer">The party that issues the token.</param>
/// <param name="Audience">The intended recipient of the token.</param>
/// <param name="Secret">The secret key used to sign and validate the token.</param>
/// <param name="Claims">The claims, as key/value pairs, to embed in the token.</param>
public record JwtConfiguration(double ExpirationInSeconds, string Issuer, string Audience, string Secret, Dictionary<string, string> Claims)
{
    /// <summary>
    /// Initializes a new instance of the <see cref="JwtConfiguration"/> record with empty default values.
    /// </summary>
    public JwtConfiguration() : this(0, string.Empty, string.Empty, string.Empty, new Dictionary<string, string>()) { }
}
