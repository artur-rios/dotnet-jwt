namespace ArturRios.Jwt.Tests;

/// <summary>
/// RFC 7638 JWK thumbprints, the id every ES256 key carries, checked against the RFC's own example.
/// </summary>
[Trait("Category", "Unit")]
public class JwkThumbprintTests
{
    /// <summary>RFC 7638, Section 3.1: the example RSA key's modulus, joined from the RFC's display lines.</summary>
    private const string Rfc7638N =
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

    /// <summary>RFC 7638, Section 3.1: the thumbprint the RFC computes for that key.</summary>
    private const string Rfc7638Thumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

    private static Dictionary<string, string> Rfc7638Members() => new()
    {
        // Deliberately not in lexicographic order: ordering is the computation's job.
        ["kty"] = "RSA",
        ["n"] = Rfc7638N,
        ["e"] = "AQAB"
    };

    [Fact]
    public void GivenTheRfc7638ExampleKey_WhenItsRequiredMembersAreSerialised_ThenTheJsonIsTheRfcsIntermediateObject()
    {
        var json = JwkThumbprint.CanonicalJson(Rfc7638Members());

        Assert.Equal("{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"" + Rfc7638N + "\"}", json);
    }

    [Fact]
    public void GivenTheRfc7638ExampleKey_WhenThumbprinted_ThenTheResultIsTheRfcs()
    {
        Assert.Equal(Rfc7638Thumbprint, JwkThumbprint.Compute(Rfc7638Members()));
    }

    [Fact]
    public void GivenTheRfc7515AppendixA3Key_WhenThumbprintedAsP256_ThenTheResultIsTheCrossCheckedValue()
    {
        Assert.Equal(TestKeys.Rfc7515Thumbprint, JwkThumbprint.ForP256(TestKeys.Rfc7515X, TestKeys.Rfc7515Y));
    }

    [Fact]
    public void GivenTwoDifferentKeys_WhenThumbprinted_ThenTheThumbprintsDiffer()
    {
        var other = JwkThumbprint.ForP256(TestKeys.Rfc7515Y, TestKeys.Rfc7515X);

        Assert.NotEqual(TestKeys.Rfc7515Thumbprint, other);
    }
}
