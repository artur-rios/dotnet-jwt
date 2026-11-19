using System.Buffers.Text;
using System.Security.Cryptography;

namespace ArturRios.Jwt.Tests;

/// <summary>
/// The P-256 curve check every public key passes before it is used: a point off the curve is the
/// precondition of invalid-curve attacks, so it is refused rather than handed to the platform.
/// </summary>
[Trait("Category", "Unit")]
public class P256Tests
{
    private static byte[] Decode(string value) => Base64Url.DecodeFromChars(value);

    [Fact]
    public void GivenTheNistP256Curve_WhenChecked_ThenItIsNamedP256()
    {
        Assert.True(P256.IsNamed(ECCurve.NamedCurves.nistP256));
    }

    [Fact]
    public void GivenTheNistP384Curve_WhenChecked_ThenItIsNotNamedP256()
    {
        Assert.False(P256.IsNamed(ECCurve.NamedCurves.nistP384));
    }

    [Fact]
    public void GivenTheRfc7515AppendixA3Point_WhenChecked_ThenItIsOnTheCurve()
    {
        Assert.True(P256.IsOnCurve(Decode(TestKeys.Rfc7515X), Decode(TestKeys.Rfc7515Y)));
    }

    [Fact]
    public void GivenAYOneBitOff_WhenChecked_ThenThePointIsNotOnTheCurve()
    {
        Assert.False(P256.IsOnCurve(Decode(TestKeys.Rfc7515X), Decode(TestKeys.OffCurveY)));
    }

    [Fact]
    public void GivenACoordinateShorterThan32Bytes_WhenChecked_ThenThePointIsRefused()
    {
        Assert.False(P256.IsOnCurve(Decode(TestKeys.Rfc7515X)[..31], Decode(TestKeys.Rfc7515Y)));
    }

    [Fact]
    public void GivenAYShorterThan32BytesThatStillEncodesAPointOnTheCurve_WhenChecked_ThenThePointIsRefused()
    {
        var x = Decode(TestKeys.LeadingZeroYX);
        var y = Decode(TestKeys.LeadingZeroY);

        // y's first byte is zero, so its last 31 bytes are the same number: only the length check refuses it.
        Assert.True(P256.IsOnCurve(x, y));
        Assert.Equal(0, y[0]);
        Assert.False(P256.IsOnCurve(x, y[1..]));
    }

    [Fact]
    public void GivenAnXOf33BytesThatStillEncodesAPointOnTheCurve_WhenChecked_ThenThePointIsRefused()
    {
        byte[] x = [0, .. Decode(TestKeys.Rfc7515X)];

        Assert.False(P256.IsOnCurve(x, Decode(TestKeys.Rfc7515Y)));
    }

    [Fact]
    public void GivenAYOf33BytesThatStillEncodesAPointOnTheCurve_WhenChecked_ThenThePointIsRefused()
    {
        byte[] y = [0, .. Decode(TestKeys.Rfc7515Y)];

        Assert.False(P256.IsOnCurve(Decode(TestKeys.Rfc7515X), y));
    }

    [Fact]
    public void GivenCoordinatesAtOrAboveTheFieldPrime_WhenChecked_ThenThePointIsRefused()
    {
        var allOnes = Enumerable.Repeat((byte)0xFF, 32).ToArray();

        Assert.False(P256.IsOnCurve(allOnes, allOnes));
    }

    [Theory]
    [InlineData("nistP256")]
    [InlineData("ECDSA_P256")]
    [InlineData("prime256v1")]
    [InlineData("secp256r1")]
    public void GivenP256NamedByOneOfItsFriendlyNames_WhenChecked_ThenItIsNamedP256(string friendlyName)
    {
        // Whether the platform resolves the name to the OID or not, the name alone is enough.
        Assert.True(P256.IsNamed(ECCurve.CreateFromFriendlyName(friendlyName)));
    }

    [Fact]
    public void GivenP256NamedByItsOidAlone_WhenChecked_ThenItIsNamedP256()
    {
        Assert.True(P256.IsNamed(ECCurve.CreateFromValue(P256.Oid)));
    }

    [Theory]
    [InlineData("nistP384")]
    [InlineData("brainpoolP256r1")]
    public void GivenAnotherNamedCurve_WhenChecked_ThenItIsNotNamedP256(string friendlyName)
    {
        Assert.False(P256.IsNamed(ECCurve.CreateFromFriendlyName(friendlyName)));
    }

    [Fact]
    public void GivenP256GivenByItsExplicitParameters_WhenChecked_ThenItIsNotNamedP256()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var explicitCurve = key.ExportExplicitParameters(includePrivateParameters: false).Curve;

        Assert.False(P256.IsNamed(explicitCurve));
    }
}
