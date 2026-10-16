using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace ArturRios.Jwt;

/// <summary>
/// A key and the identifier that names it, so a token can say which key signed it and a validator can
/// accept more than one. An HS256 key is a shared secret; an ES256 key is an EC P-256 key pair, or the
/// public half of one.
/// </summary>
/// <remarks>
/// <para>
/// The identifier exists to make key rotation possible. Signing with one key while still accepting
/// another is what turns replacing a key from a cutover — where every token in flight becomes invalid
/// at once — into a rotation. The identifier is written to the token's <c>kid</c> header, and it selects
/// a key and nothing else: the signature still decides whether the token is valid.
/// </para>
/// <para>
/// <b>ES256 keys</b> come from <see cref="FromEcPrivateKeyPem"/> or <see cref="FromEcPublicJwk"/>, never
/// from the constructor. Their <see cref="Id"/> is their RFC 7638 <see cref="Thumbprint"/>, derived from
/// the public half, so it stays attached to the same key wherever the key is published and is never
/// configured; their <see cref="Secret"/> is empty. A <see langword="with"/> expression that changes
/// either makes a key no published key set will match, and <see cref="JwtConfigurationValidator"/>
/// refuses one whose id is not its thumbprint.
/// </para>
/// <para>
/// An ES256 key holds its platform <see cref="ECDsa"/> for its whole life and is not
/// <see cref="IDisposable"/>: keys are long-lived configuration, and the record must stay binary
/// compatible with consumers built against the HS256-only one. The cost is one unmanaged handle per key
/// object, released when it is finalized, so read a key once and keep it rather than reading it per request.
/// </para>
/// <para>
/// Each key validates its own algorithm only — a secret HS256, an EC key ES256 — whatever a token's
/// <c>alg</c> header says. That is what makes the classic confusion, an HS256 token keyed with a
/// published public key, fail by construction.
/// </para>
/// </remarks>
/// <param name="Id">Names the key. Written to the token's <c>kid</c> header, so keep it stable and free of secrets.</param>
/// <param name="Secret">The secret used to sign and validate HS256. HMAC-SHA256 needs at least 32 bytes. Empty for an ES256 key.</param>
public record JwtKey(string Id, string Secret)
{
    private const string NotAP256PrivateKey =
        "The PEM is not a P-256 (prime256v1) private key. Generate one with " +
        "'openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256'.";

    private const string NotAP256Point =
        "The coordinates are not a point on P-256: each must be the base64url encoding of 32 bytes, and " +
        "together they must satisfy the curve's equation.";

    private readonly ECDsa? _ecdsa;
    private readonly bool _hasPrivateKey;

    private JwtKey(ECDsa ecdsa, string x, string y, bool hasPrivateKey)
        : this(JwkThumbprint.ForP256(x, y), string.Empty)
    {
        _ecdsa = ecdsa;
        _hasPrivateKey = hasPrivateKey;
        PublicX = x;
        PublicY = y;
    }

    /// <summary>The one algorithm this key signs and validates: HS256 for a secret, ES256 for an EC key.</summary>
    public string Algorithm => _ecdsa is null ? JwtAlgorithms.HS256 : JwtAlgorithms.ES256;

    /// <summary>Whether this is an ES256 key rather than an HS256 secret.</summary>
    public bool IsAsymmetric => _ecdsa is not null;

    /// <summary>
    /// Whether this key can sign: a secret that is not blank, or an EC key holding its private half. A
    /// public key read from a key set validates but cannot sign.
    /// </summary>
    public bool CanSign => _ecdsa is null ? !string.IsNullOrWhiteSpace(Secret) : _hasPrivateKey;

    /// <summary>The RFC 7638 thumbprint of an ES256 key's public half; <see langword="null"/> for a secret.</summary>
    public string? Thumbprint => PublicX is null || PublicY is null ? null : JwkThumbprint.ForP256(PublicX, PublicY);

    /// <summary>The base64url x coordinate of an ES256 key's public half.</summary>
    internal string? PublicX { get; }

    /// <summary>The base64url y coordinate of an ES256 key's public half.</summary>
    internal string? PublicY { get; }

    /// <summary>
    /// Reads an ES256 signing key from a PEM: PKCS#8 (<c>BEGIN PRIVATE KEY</c>, what <c>openssl genpkey</c>
    /// writes) or SEC1 (<c>BEGIN EC PRIVATE KEY</c>).
    /// </summary>
    /// <param name="pem">The private key. Its contents never appear in an exception message.</param>
    /// <exception cref="ArgumentException">
    /// The PEM is unreadable, holds no private key, or holds a key on any curve but P-256.
    /// </exception>
    public static JwtKey FromEcPrivateKeyPem(string pem)
    {
        ArgumentNullException.ThrowIfNull(pem);

        ECParameters parameters;

        using (var imported = ECDsa.Create())
        {
            try
            {
                imported.ImportFromPem(pem);
                parameters = imported.ExportParameters(includePrivateParameters: true);
            }
            catch (Exception exception) when (exception is ArgumentException or CryptographicException)
            {
                // The platform's message is replaced, not wrapped: what matters is which key to supply,
                // and nothing derived from the input should travel further than this method.
                throw new ArgumentException(NotAP256PrivateKey, nameof(pem));
            }
        }

        try
        {
            if (parameters.D is null || !P256.IsNamed(parameters.Curve) ||
                !P256.IsOnCurve(parameters.Q.X, parameters.Q.Y))
            {
                throw new ArgumentException(NotAP256PrivateKey, nameof(pem));
            }

            var ecdsa = ECDsa.Create(new ECParameters { Curve = P256.Curve, Q = parameters.Q, D = parameters.D });

            return new JwtKey(ecdsa, Base64Url.EncodeToString(parameters.Q.X), Base64Url.EncodeToString(parameters.Q.Y),
                hasPrivateKey: true);
        }
        finally
        {
            if (parameters.D is not null)
            {
                CryptographicOperations.ZeroMemory(parameters.D);
            }
        }
    }

    /// <summary>
    /// Builds an ES256 verification key from a P-256 JWK's <c>x</c> and <c>y</c> members, as a JSON Web Key
    /// Set publishes them.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// A coordinate is not base64url, is not 32 bytes, or the point is not on P-256.
    /// </exception>
    public static JwtKey FromEcPublicJwk(string x, string y)
    {
        ArgumentNullException.ThrowIfNull(x);
        ArgumentNullException.ThrowIfNull(y);

        byte[] xBytes;
        byte[] yBytes;

        try
        {
            xBytes = Base64Url.DecodeFromChars(x);
            yBytes = Base64Url.DecodeFromChars(y);
        }
        catch (FormatException)
        {
            throw new ArgumentException(NotAP256Point);
        }

        if (!P256.IsOnCurve(xBytes, yBytes))
        {
            throw new ArgumentException(NotAP256Point);
        }

        var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = P256.Curve,
            Q = new ECPoint { X = xBytes, Y = yBytes }
        });

        // Re-encoded from the bytes, so the thumbprint is computed over the canonical encoding whatever
        // padding or spelling the source used.
        return new JwtKey(ecdsa, Base64Url.EncodeToString(xBytes), Base64Url.EncodeToString(yBytes), hasPrivateKey: false);
    }

    /// <summary>The public half of an ES256 key, under the same id: what may be published and handed to validators.</summary>
    /// <exception cref="InvalidOperationException">This is an HS256 secret, which has no public half.</exception>
    public JwtKey ToPublicKey() =>
        PublicX is null || PublicY is null
            ? throw new InvalidOperationException(
                "An HS256 key is a shared secret: it has no public half, and publishing it would let anyone sign.")
            : FromEcPublicJwk(PublicX, PublicY) with { Id = Id };

    /// <summary>
    /// The key as Microsoft.IdentityModel uses it, carrying <see cref="Id"/> as its <c>KeyId</c>: an
    /// <see cref="ECDsaSecurityKey"/> for an ES256 key, or a <see cref="SymmetricSecurityKey"/> over the
    /// secret's ASCII bytes — the bytes <see cref="JwtHandler"/> has always signed with — for an HS256 one.
    /// </summary>
    /// <remarks>
    /// Pair it with exactly one algorithm, this key's <see cref="Algorithm"/>, as <see cref="JwtHandler"/>
    /// does: accepting both algorithms against both kinds of key is what an algorithm-confusion attack needs.
    /// </remarks>
    /// <exception cref="InvalidOperationException">An HS256 key whose secret is blank.</exception>
    public SecurityKey ToSecurityKey()
    {
        if (_ecdsa is not null)
        {
            return new ECDsaSecurityKey(_ecdsa) { KeyId = Id };
        }

        if (string.IsNullOrWhiteSpace(Secret))
        {
            throw new InvalidOperationException("A key with a blank secret signs nothing and accepts nothing.");
        }

        return new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Secret)) { KeyId = Id };
    }

    /// <summary>
    /// Equal when the id, the secret and the public key match and both can, or both cannot, sign. The
    /// platform key object behind an ES256 key is not compared, so two keys read from one PEM are equal.
    /// </summary>
    public virtual bool Equals(JwtKey? other) =>
        other is not null &&
        EqualityContract == other.EqualityContract &&
        Id == other.Id &&
        Secret == other.Secret &&
        PublicX == other.PublicX &&
        PublicY == other.PublicY &&
        CanSign == other.CanSign;

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(EqualityContract, Id, Secret, PublicX, PublicY, CanSign);
}
