namespace ArturRios.Jwt;

/// <summary>
/// Configuration used to create and validate JSON Web Tokens.
/// </summary>
/// <remarks>
/// <para>
/// There are two ways to supply key material, and the second is a superset of the first.
/// <see cref="Secret"/> alone signs and validates with one key, which is all a deployment that never
/// rotates needs. <see cref="Keys"/> with <see cref="SigningKeyId"/> signs with one key and accepts
/// several, which is what makes a rotation possible: add the new key everywhere, switch the signing
/// key, then drop the old one once no token signed with it can still be alive.
/// </para>
/// <para>
/// Leaving <see cref="Keys"/> empty behaves exactly as it did before the property existed, so
/// nothing changes for a configuration that does not use it.
/// </para>
/// </remarks>
/// <param name="ExpirationInSeconds">The number of seconds after creation for which the token remains valid.</param>
/// <param name="Issuer">The party that issues the token.</param>
/// <param name="Audience">The intended recipient of the token.</param>
/// <param name="Secret">The secret key used to sign and validate the token. Ignored when <see cref="SigningKeyId"/> names a key in <see cref="Keys"/>.</param>
/// <param name="Claims">The claims, as key/value pairs, to embed in the token.</param>
public record JwtConfiguration(double ExpirationInSeconds, string Issuer, string Audience, string Secret, Dictionary<string, string> Claims)
{
    /// <summary>
    /// Initializes a new instance of the <see cref="JwtConfiguration"/> record with empty default values.
    /// </summary>
    public JwtConfiguration() : this(0, string.Empty, string.Empty, string.Empty, new Dictionary<string, string>()) { }

    /// <summary>
    /// Every key whose signature is accepted when validating. Empty by default, which keeps
    /// <see cref="Secret"/> as the only key.
    /// </summary>
    /// <remarks>
    /// A key stays here for as long as tokens it signed may still be alive — one token lifetime after
    /// it stops being the signing key. Removing it earlier invalidates those tokens immediately,
    /// which is the right thing to do when a key has leaked and the wrong thing to do when it is
    /// merely being replaced.
    /// </remarks>
    public IReadOnlyCollection<JwtKey> Keys { get; init; } = [];

    /// <summary>
    /// The <see cref="JwtKey.Id"/> of the key in <see cref="Keys"/> that signs new tokens, written to
    /// each token's <c>kid</c> header. When empty, tokens are signed with <see cref="Secret"/> and
    /// carry no <c>kid</c> — so with <see cref="Keys"/> set, <see cref="Secret"/> must be the secret of
    /// one of them, or nothing validating against <see cref="Keys"/> accepts the tokens.
    /// </summary>
    /// <remarks>
    /// Rotating is a change to this property alone: the key it names must already be in
    /// <see cref="Keys"/> — <see cref="JwtConfigurationValidator"/> requires it — so the new key is
    /// accepted everywhere before anything starts signing with it.
    /// </remarks>
    public string? SigningKeyId { get; init; }
}
