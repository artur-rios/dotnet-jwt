using System.Text;
using System.Text.Json;

namespace ArturRios.Jwt;

/// <summary>
/// JSON Web Key Sets (RFC 7517) of ES256 public keys: what an issuer publishes so that others can verify
/// its tokens without holding anything that signs them, and what those others read.
/// </summary>
/// <remarks>
/// Every member written is a fixed ASCII name or a base64url value (a coordinate, or an id that is a
/// thumbprint), so the default <see cref="Utf8JsonWriter"/> encoder, which escapes <c>+ &lt; &gt; &amp; '</c>
/// and non-ASCII characters, never changes any of them.
/// </remarks>
public static class JwksDocument
{
    private const string Kty = "kty";
    private const string Crv = "crv";
    private const string X = "x";
    private const string Y = "y";
    private const string Kid = "kid";
    private const string Use = "use";
    private const string Alg = "alg";
    private const string PrivateScalar = "d";
    private const string Signature = "sig";

    /// <summary>
    /// The key set publishing the public halves of <paramref name="keys"/>, in order: <c>kty</c>,
    /// <c>crv</c>, <c>x</c>, <c>y</c>, <c>kid</c> (the key's id), <c>use</c> (<c>sig</c>) and <c>alg</c>
    /// (<c>ES256</c>) for each. A private half is never written, whether the key holds one or not.
    /// </summary>
    /// <exception cref="ArgumentException">A key is an HS256 secret, which has no public half to publish.</exception>
    public static string From(IEnumerable<JwtKey> keys)
    {
        ArgumentNullException.ThrowIfNull(keys);

        var published = keys.ToList();

        if (published.Any(key => !key.IsAsymmetric))
        {
            throw new ArgumentException(
                $"An {JwtAlgorithms.HS256} key is a shared secret with no public half: a key set publishes {JwtAlgorithms.ES256} keys only.",
                nameof(keys));
        }

        using var buffer = new MemoryStream();

        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteStartArray("keys");

            foreach (var key in published)
            {
                writer.WriteStartObject();

                JwkThumbprint.WriteMembers(writer, new KeyValuePair<string, string>[]
                {
                    new(Kty, "EC"),
                    new(Crv, P256.JwkCurveName),
                    new(X, key.PublicX!),
                    new(Y, key.PublicY!),
                    new(Kid, key.Id),
                    new(Use, Signature),
                    new(Alg, JwtAlgorithms.ES256)
                });

                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    /// <summary>
    /// Reads the ES256 verification keys a key set publishes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An entry is read when it is an EC key on P-256 whose <c>use</c>, if present, is <c>sig</c>, whose
    /// <c>alg</c>, if present, is <c>ES256</c>, whose point is on the curve, and whose <c>kid</c>, if
    /// present, is its RFC 7638 thumbprint. Any other entry is skipped, not an error: a key set may
    /// publish keys for other uses, and a key that cannot be used safely must not validate anything.
    /// </para>
    /// <para>
    /// An entry that carries a <c>d</c> member is skipped too: a published private part means the key is
    /// compromised, and trusting its public half would accept anyone's forgeries. Each key is returned
    /// once; a later entry with the same id (the thumbprint, so the same key) is skipped. A parsed key
    /// can verify but never sign.
    /// </para>
    /// <para>
    /// Text that JSON accepts but cannot be decoded, such as a lone surrogate escape in a name or value,
    /// skips its entry, or is a <see cref="FormatException"/> when it is in the key set's own members.
    /// </para>
    /// </remarks>
    /// <exception cref="FormatException">The text is not JSON, or not an object with a <c>keys</c> array.</exception>
    public static IReadOnlyList<JwtKey> Parse(string json)
    {
        ArgumentNullException.ThrowIfNull(json);

        JsonDocument document;

        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException)
        {
            throw new FormatException("The key set is not JSON.");
        }

        using (document)
        {
            var root = document.RootElement;

            var entries = default(JsonElement);
            var isKeySet = false;

            try
            {
                isKeySet = root.ValueKind == JsonValueKind.Object &&
                           root.TryGetProperty("keys", out entries) &&
                           entries.ValueKind == JsonValueKind.Array;
            }
            catch (InvalidOperationException)
            {
                throw new FormatException("The key set has a member name that is not valid text.");
            }

            if (!isKeySet)
            {
                throw new FormatException("A key set is a JSON object with a \"keys\" array.");
            }

            var keys = new List<JwtKey>();

            foreach (var entry in entries.EnumerateArray())
            {
                if (TryRead(entry) is { } key && keys.All(read => read.Id != key.Id))
                {
                    keys.Add(key);
                }
            }

            return keys;
        }
    }

    /// <summary>The verification key an entry describes, or <see langword="null"/> when it is not one to use.</summary>
    private static JwtKey? TryRead(JsonElement entry)
    {
        try
        {
            return ReadEntry(entry);
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    private static JwtKey? ReadEntry(JsonElement entry)
    {
        if (entry.ValueKind != JsonValueKind.Object ||
            entry.TryGetProperty(PrivateScalar, out _) ||
            Required(entry, Kty) != "EC" ||
            Required(entry, Crv) != P256.JwkCurveName ||
            !OptionalIs(entry, Use, Signature) ||
            !OptionalIs(entry, Alg, JwtAlgorithms.ES256) ||
            Required(entry, X) is not { } x ||
            Required(entry, Y) is not { } y)
        {
            return null;
        }

        JwtKey key;

        try
        {
            key = JwtKey.FromEcPublicJwk(x, y);
        }
        catch (ArgumentException)
        {
            return null;
        }

        return OptionalIs(entry, Kid, key.Id) ? key : null;
    }

    /// <summary>A member's string value, or <see langword="null"/> when it is absent or not a string.</summary>
    private static string? Required(JsonElement entry, string name) =>
        entry.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    /// <summary>Whether a member is absent, or present as exactly <paramref name="expected"/>.</summary>
    private static bool OptionalIs(JsonElement entry, string name, string expected) =>
        !entry.TryGetProperty(name, out var value) ||
        (value.ValueKind == JsonValueKind.String && value.GetString() == expected);
}
