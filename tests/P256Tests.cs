using System.Buffers.Text;

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
    public void GivenCoordinatesAtOrAboveTheFieldPrime_WhenChecked_ThenThePointIsRefused()
    {
        var allOnes = Enumerable.Repeat((byte)0xFF, 32).ToArray();

        Assert.False(P256.IsOnCurve(allOnes, allOnes));
    }
}
