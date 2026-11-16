namespace ArturRios.Jwt.Tests;

[Trait("Category", "Unit")]
public class JwtConfigurationTests
{
    [Fact]
    public void GivenNoArguments_WhenConfigurationIsConstructed_ThenDefaultValuesAreSet()
    {
        var configuration = new JwtConfiguration();

        Assert.Equal(0, configuration.ExpirationInSeconds);
        Assert.Equal(string.Empty, configuration.Issuer);
        Assert.Equal(string.Empty, configuration.Audience);
        Assert.Equal(string.Empty, configuration.Secret);
        Assert.Empty(configuration.Claims);
    }

    [Fact]
    public void GivenArguments_WhenConfigurationIsConstructed_ThenPropertiesAreSetFromArguments()
    {
        const double expirationInSeconds = 3600;
        const string issuer = "issuer";
        const string audience = "audience";
        const string secret = "secret";
        var claims = new Dictionary<string, string> { { "id", "1" } };

        var configuration = new JwtConfiguration(expirationInSeconds, issuer, audience, secret, claims);

        Assert.Equal(expirationInSeconds, configuration.ExpirationInSeconds);
        Assert.Equal(issuer, configuration.Issuer);
        Assert.Equal(audience, configuration.Audience);
        Assert.Equal(secret, configuration.Secret);
        Assert.Equal(claims, configuration.Claims);
    }

    [Fact]
    public void GivenTwoConfigurationsWithSameValues_WhenConfigurationsAreCompared_ThenTheyAreEqual()
    {
        var claims = new Dictionary<string, string> { { "id", "1" } };
        var first = new JwtConfiguration(3600, "issuer", "audience", "secret", claims);
        var second = new JwtConfiguration(3600, "issuer", "audience", "secret", claims);

        var areEqual = first.Equals(second);

        Assert.True(areEqual);
    }

    [Fact]
    public void GivenTwoConfigurationsWithDifferentValues_WhenConfigurationsAreCompared_ThenTheyAreNotEqual()
    {
        var first = new JwtConfiguration(3600, "issuer", "audience", "secret", new Dictionary<string, string>());
        var second = new JwtConfiguration(1800, "other-issuer", "other-audience", "other-secret", new Dictionary<string, string>());

        var areEqual = first.Equals(second);

        Assert.False(areEqual);
    }

    [Fact]
    public void GivenNoArguments_WhenConfigurationIsConstructed_ThenItHasNoKeysNoSigningKeyAndSignsHs256()
    {
        var configuration = new JwtConfiguration();

        Assert.Empty(configuration.Keys);
        Assert.Null(configuration.SigningKeyId);
        Assert.Equal(JwtAlgorithms.HS256, configuration.Algorithm);
    }

    [Fact]
    public void GivenTwoConfigurationsWithEqualClaimsInSeparateDictionaries_WhenCompared_ThenTheyAreNotEqual()
    {
        // A record compares its collections by reference, not by content.
        var first = new JwtConfiguration(3600, "issuer", "audience", "secret", new Dictionary<string, string> { { "id", "1" } });
        var second = new JwtConfiguration(3600, "issuer", "audience", "secret", new Dictionary<string, string> { { "id", "1" } });

        Assert.NotEqual(first, second);
    }

    [Theory]
    [InlineData(nameof(JwtConfiguration.Keys))]
    [InlineData(nameof(JwtConfiguration.SigningKeyId))]
    [InlineData(nameof(JwtConfiguration.Algorithm))]
    public void GivenTwoConfigurationsDifferingInOneInitProperty_WhenCompared_ThenTheyAreNotEqual(string property)
    {
        var first = new JwtConfiguration();

        var second = property switch
        {
            nameof(JwtConfiguration.Keys) => first with { Keys = [new JwtKey("k1", "secret")] },
            nameof(JwtConfiguration.SigningKeyId) => first with { SigningKeyId = "k1" },
            _ => first with { Algorithm = JwtAlgorithms.ES256 }
        };

        Assert.NotEqual(first, second);
        Assert.Equal(first, first with { });
    }
}
