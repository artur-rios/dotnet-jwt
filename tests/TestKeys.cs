using System.Buffers.Text;
using System.Security.Cryptography;

namespace ArturRios.Jwt.Tests;

/// <summary>
/// Key material for the tests: freshly generated P-256 keys, and the example key and JWS of RFC 7515,
/// Appendix A.3, copied from the RFC.
/// </summary>
internal static class TestKeys
{
    /// <summary>RFC 7515, Appendix A.3.1: the example key's public x coordinate.</summary>
    public const string Rfc7515X = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";

    /// <summary>RFC 7515, Appendix A.3.1: the example key's public y coordinate.</summary>
    public const string Rfc7515Y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

    /// <summary>RFC 7515, Appendix A.3.1: the example key's private scalar.</summary>
    public const string Rfc7515D = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";

    /// <summary>RFC 7515, Appendix A.3.1: the complete JWS, header <c>{"alg":"ES256"}</c>, signed with the key above.</summary>
    public const string Rfc7515Jws =
        "eyJhbGciOiJFUzI1NiJ9" +
        ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
        ".DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

    /// <summary>
    /// The RFC 7638 thumbprint of the key above. Neither RFC prints it: it was computed with RFC 7638's
    /// procedure over <c>{"crv":"P-256","kty":"EC","x":"…","y":"…"}</c> and cross-checked with an independent
    /// implementation (Python's hashlib) over the same bytes.
    /// </summary>
    public const string Rfc7515Thumbprint = "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U";

    /// <summary>The example key's y with its last bit flipped: not a point on P-256.</summary>
    public const string OffCurveY = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5aw";

    /// <summary>A new P-256 private key as a PKCS#8 PEM, what <c>openssl genpkey</c> writes.</summary>
    public static string NewP256Pem()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        return key.ExportPkcs8PrivateKeyPem();
    }

    /// <summary>The RFC 7515 A.3 example key as a PKCS#8 PEM.</summary>
    public static string Rfc7515Pem()
    {
        using var key = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = Base64Url.DecodeFromChars(Rfc7515X), Y = Base64Url.DecodeFromChars(Rfc7515Y) },
            D = Base64Url.DecodeFromChars(Rfc7515D)
        });

        return key.ExportPkcs8PrivateKeyPem();
    }

    /// <summary>A new ES256 signing key.</summary>
    public static JwtKey NewEs256Key() => JwtKey.FromEcPrivateKeyPem(NewP256Pem());
}
