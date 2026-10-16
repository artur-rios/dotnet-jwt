using System.Text.Json;

namespace ArturRios.Jwt.Tests;

/// <summary>
/// JSON Web Key Sets: what a publisher writes (public halves only, never a secret) and what a consumer
/// reads (EC P-256 signing keys whose kid is their thumbprint, and nothing else).
/// </summary>
[Trait("Category", "Unit")]
public class JwksDocumentTests
{
    private static JsonElement[] Entries(string json) =>
        JsonDocument.Parse(json).RootElement.GetProperty("keys").EnumerateArray().ToArray();

    private static string Entry(string members) => $"{{\"keys\":[{members}]}}";

    private static string Rfc7515Entry(string extra = "") =>
        $"{{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{TestKeys.Rfc7515X}\",\"y\":\"{TestKeys.Rfc7515Y}\"{extra}}}";

    [Fact]
    public void GivenTwoKeys_WhenPublished_ThenEachEntryIsAnEs256SigningKeyNamedByItsThumbprint()
    {
        var current = TestKeys.NewEs256Key();
        var previous = TestKeys.NewEs256Key();

        var entries = Entries(JwksDocument.From([current, previous]));

        Assert.Equal(2, entries.Length);
        Assert.All(entries, entry =>
        {
            Assert.Equal("EC", entry.GetProperty("kty").GetString());
            Assert.Equal("P-256", entry.GetProperty("crv").GetString());
            Assert.Equal("sig", entry.GetProperty("use").GetString());
            Assert.Equal("ES256", entry.GetProperty("alg").GetString());
            Assert.False(entry.TryGetProperty("d", out _));
        });
        Assert.Equal([current.Id, previous.Id], entries.Select(entry => entry.GetProperty("kid").GetString()));
    }

    [Fact]
    public void GivenAPrivateKey_WhenPublished_ThenItsPrivateScalarIsNowhereInTheDocument()
    {
        var json = JwksDocument.From([JwtKey.FromEcPrivateKeyPem(TestKeys.Rfc7515Pem())]);

        Assert.DoesNotContain(TestKeys.Rfc7515D, json);
        Assert.DoesNotContain("\"d\"", json);
    }

    [Fact]
    public void GivenASecretKey_WhenPublished_ThenItIsRefused()
    {
        Assert.Throws<ArgumentException>(() =>
            JwksDocument.From([new JwtKey("k1", TestKeys.Secret)]));
    }

    [Fact]
    public void GivenAKeyRenamedAwayFromItsThumbprint_WhenPublished_ThenItIsRefusedWithoutEchoingIt()
    {
        var renamed = TestKeys.NewEs256Key() with { Id = "renamed" };

        var refusal = Assert.Throws<ArgumentException>(() => JwksDocument.From([TestKeys.NewEs256Key(), renamed]));

        Assert.Equal("keys", refusal.ParamName);
        Assert.DoesNotContain("renamed", refusal.Message);
        Assert.DoesNotContain(renamed.PublicX!, refusal.Message);
        Assert.DoesNotContain(renamed.Thumbprint!, refusal.Message);
    }

    [Fact]
    public void GivenANullKey_WhenPublished_ThenItIsRefusedAsAnArgument()
    {
        var refusal = Assert.Throws<ArgumentException>(() => JwksDocument.From([TestKeys.NewEs256Key(), null!]));

        Assert.Equal("keys", refusal.ParamName);
    }

    [Fact]
    public void GivenNoKeys_WhenPublished_ThenTheSetIsEmpty()
    {
        Assert.Equal("{\"keys\":[]}", JwksDocument.From([]));
    }

    [Fact]
    public void GivenAPublishedSet_WhenParsed_ThenTheSameKeysComeBackAsPublicKeys()
    {
        var current = TestKeys.NewEs256Key();
        var previous = TestKeys.NewEs256Key();

        var parsed = JwksDocument.Parse(JwksDocument.From([current, previous]));

        Assert.Equal([current.ToPublicKey(), previous.ToPublicKey()], parsed);
        Assert.All(parsed, key => Assert.False(key.CanSign));
    }

    [Fact]
    public void GivenAnEntryPublishingItsPrivateScalar_WhenParsed_ThenTheEntryIsSkipped()
    {
        Assert.Empty(JwksDocument.Parse(Entry(Rfc7515Entry($",\"d\":\"{TestKeys.Rfc7515D}\""))));
    }

    [Fact]
    public void GivenTheSameKeyTwice_WhenParsed_ThenItIsReturnedOnce()
    {
        var parsed = JwksDocument.Parse(Entry($"{Rfc7515Entry()},{Rfc7515Entry()}"));

        Assert.Equal(TestKeys.Rfc7515Thumbprint, Assert.Single(parsed).Id);
    }

    [Theory]
    [InlineData("{\"kty\":\"\\uD800\"}")]
    [InlineData("{\"\\uD800\":1}")]
    [InlineData("{\"kty\":\"EC\",\"\\uD800\":1}")]
    public void GivenAnEntryWithAnUndecodableSurrogate_WhenParsed_ThenItIsSkipped(string entry)
    {
        var parsed = JwksDocument.Parse(Entry($"{entry},{Rfc7515Entry()}"));

        Assert.Equal(TestKeys.Rfc7515Thumbprint, Assert.Single(parsed).Id);
    }

    [Fact]
    public void GivenAnUndecodableMemberNameBesideTheKeys_WhenParsed_ThenItIsRefused()
    {
        Assert.Throws<FormatException>(() => JwksDocument.Parse("{\"keys\":[],\"\\uD800\":1}"));
    }

    [Theory]
    [InlineData("{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\"}")]
    [InlineData("{\"kty\":\"EC\",\"crv\":\"P-384\",\"x\":\"AA\",\"y\":\"AA\"}")]
    [InlineData("\"not an object\"")]
    public void GivenAnEntryThatIsNotAP256Key_WhenParsed_ThenItIsSkipped(string entry)
    {
        var parsed = JwksDocument.Parse(Entry($"{entry},{Rfc7515Entry()}"));

        Assert.Equal(TestKeys.Rfc7515Thumbprint, Assert.Single(parsed).Id);
    }

    [Theory]
    [InlineData(",\"use\":\"enc\"")]
    [InlineData(",\"alg\":\"ES384\"")]
    [InlineData(",\"kid\":\"not-its-thumbprint\"")]
    [InlineData(",\"use\":1")]
    public void GivenAnEntryNotUsableForEs256Signatures_WhenParsed_ThenItIsSkipped(string extra)
    {
        Assert.Empty(JwksDocument.Parse(Entry(Rfc7515Entry(extra))));
    }

    [Fact]
    public void GivenAnEntryOffTheCurve_WhenParsed_ThenItIsSkipped()
    {
        var offCurve = $"{{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{TestKeys.Rfc7515X}\",\"y\":\"{TestKeys.OffCurveY}\"}}";

        Assert.Empty(JwksDocument.Parse(Entry(offCurve)));
    }

    [Fact]
    public void GivenAnEntryWhoseKidIsItsThumbprint_WhenParsed_ThenItIsRead()
    {
        var parsed = JwksDocument.Parse(Entry(Rfc7515Entry($",\"kid\":\"{TestKeys.Rfc7515Thumbprint}\",\"use\":\"sig\",\"alg\":\"ES256\"")));

        Assert.Single(parsed);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("{}")]
    [InlineData("{\"keys\":{}}")]
    public void GivenSomethingThatIsNotAKeySet_WhenParsed_ThenItIsRefused(string json)
    {
        Assert.Throws<FormatException>(() => JwksDocument.Parse(json));
    }
}
