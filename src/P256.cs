using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

namespace ArturRios.Jwt;

/// <summary>
/// The NIST P-256 curve (secp256r1, prime256v1): its identifiers, and the check that a point lies on it.
/// </summary>
/// <remarks>
/// The check is explicit rather than left to the platform's import. A public key off the curve is the
/// precondition of invalid-curve attacks, and whether an import rejects one differs between platforms
/// and versions; the curve equation does not.
/// </remarks>
internal static class P256
{
    /// <summary>The curve's object identifier.</summary>
    public const string Oid = "1.2.840.10045.3.1.7";

    /// <summary>The curve's name in a JWK's <c>crv</c> member.</summary>
    public const string JwkCurveName = "P-256";

    /// <summary>The length of each coordinate, and of the private scalar, in bytes.</summary>
    public const int CoordinateBytes = 32;

    /// <summary>The field prime p = 2^256 − 2^224 + 2^192 + 2^96 − 1.</summary>
    private static readonly BigInteger s_p = BigInteger.Parse(
        "0ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", NumberStyles.HexNumber);

    /// <summary>The curve coefficient b of y² = x³ − 3x + b.</summary>
    private static readonly BigInteger s_b = BigInteger.Parse(
        "05ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", NumberStyles.HexNumber);

    /// <summary>The curve, as the platform names it.</summary>
    public static ECCurve Curve => ECCurve.NamedCurves.nistP256;

    /// <summary>
    /// Whether <paramref name="curve"/> is P-256. Platforms report it by OID or by one of its friendly
    /// names, so any of them counts.
    /// </summary>
    public static bool IsNamed(ECCurve curve) =>
        curve.IsNamed &&
        (curve.Oid.Value == Oid ||
         curve.Oid.FriendlyName is "nistP256" or "ECDSA_P256" or "prime256v1" or "secp256r1");

    /// <summary>
    /// Whether (<paramref name="x"/>, <paramref name="y"/>), big-endian and 32 bytes each, satisfies
    /// y² = x³ − 3x + b over P-256's field, with both coordinates below the field prime.
    /// </summary>
    public static bool IsOnCurve(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y)
    {
        if (x.Length != CoordinateBytes || y.Length != CoordinateBytes)
        {
            return false;
        }

        var px = new BigInteger(x, isUnsigned: true, isBigEndian: true);
        var py = new BigInteger(y, isUnsigned: true, isBigEndian: true);

        if (px >= s_p || py >= s_p)
        {
            return false;
        }

        var left = BigInteger.ModPow(py, 2, s_p);
        var right = (BigInteger.ModPow(px, 3, s_p) - 3 * px + s_b) % s_p;

        if (right.Sign < 0)
        {
            right += s_p;
        }

        return left == right;
    }
}
