using System.Text;
using System.Text.Json;

namespace ArturRios.Jwt;

/// <summary>JSON Web Key Sets (RFC 7517) of ES256 public keys.</summary>
public static class JwksDocument
{
    /// <summary>The key set publishing the public halves of <paramref name="keys"/>.</summary>
    public static string From(IEnumerable<JwtKey> keys)
    {
        using var buffer = new MemoryStream();

        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteStartArray("keys");

            foreach (var key in keys)
            {
                writer.WriteStartObject();
                writer.WriteString("kty", "EC");
                writer.WriteString("crv", P256.JwkCurveName);
                writer.WriteString("x", key.PublicX);
                writer.WriteString("y", key.PublicY);
                writer.WriteString("kid", key.Id);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }
}
