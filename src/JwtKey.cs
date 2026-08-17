namespace ArturRios.Jwt;

/// <summary>
/// A signing key and the identifier that names it, so a token can say which key signed it and a
/// validator can accept more than one.
/// </summary>
/// <remarks>
/// The identifier exists to make key rotation possible. Signing with one key while still accepting
/// another is what turns replacing a secret from a cutover — where every token in flight becomes
/// invalid at once — into a rotation. The identifier is written to the token's <c>kid</c> header, and
/// it selects a key and nothing else: the signature still decides whether the token is valid.
/// </remarks>
/// <param name="Id">Names the key. Written to the token's <c>kid</c> header, so keep it stable and free of secrets.</param>
/// <param name="Secret">The secret used to sign and validate. HMAC-SHA256 needs at least 32 bytes.</param>
public record JwtKey(string Id, string Secret);
