namespace ArturRios.Jwt;

/// <summary>
/// The signing algorithms this library creates and validates tokens with, as they appear in a token's
/// <c>alg</c> header.
/// </summary>
public static class JwtAlgorithms
{
    /// <summary>HMAC with SHA-256: one shared secret both signs and validates. The default.</summary>
    public const string HS256 = "HS256";

    /// <summary>
    /// ECDSA on the P-256 curve with SHA-256: a private key signs, and its public half, which can be
    /// published, validates.
    /// </summary>
    public const string ES256 = "ES256";
}
