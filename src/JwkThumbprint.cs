using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ArturRios.Jwt;

/// <summary>
/// RFC 7638 JWK thumbprints: the SHA-256 of a key's required members, in lexicographic order, as
/// compact JSON, base64url-encoded. It is the id an ES256 key carries, so the id is derived from the
/// key itself and never configured.
/// </summary>
internal static class JwkThumbprint
{
    /// <summary>
    /// The JSON object RFC 7638 hashes: the given members only, ordered by name (ordinal, which is
    /// Unicode code point order for the ASCII names a JWK uses), with no whitespace.
    /// </summary>
    public static string CanonicalJson(IReadOnlyDictionary<string, string> requiredMembers)
    {
        using var buffer = new MemoryStream();

        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            WriteMembers(writer, requiredMembers.OrderBy(member => member.Key, StringComparer.Ordinal));
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    /// <summary>
    /// Writes string members into the object the writer has open, in the order given. Shared with the
    /// key set writer so a JWK is serialized by one piece of code.
    /// </summary>
    /// <remarks>
    /// Every name is a fixed ASCII JWK member name and every value is base64url or a fixed ASCII word, so
    /// the writer's default encoder, which escapes <c>+ &lt; &gt; &amp; '</c> and non-ASCII characters,
    /// never changes them, and RFC 7638's unescaped serialization is what is hashed.
    /// </remarks>
    internal static void WriteMembers(Utf8JsonWriter writer, IEnumerable<KeyValuePair<string, string>> members)
    {
        foreach (var (name, value) in members)
        {
            writer.WriteString(name, value);
        }
    }

    /// <summary>The thumbprint of a key given by its required members.</summary>
    public static string Compute(IReadOnlyDictionary<string, string> requiredMembers) =>
        Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalJson(requiredMembers))));

    /// <summary>The thumbprint of a P-256 public key given by its base64url coordinates.</summary>
    public static string ForP256(string x, string y) =>
        Compute(new Dictionary<string, string>
        {
            ["crv"] = P256.JwkCurveName,
            ["kty"] = "EC",
            ["x"] = x,
            ["y"] = y
        });
}
