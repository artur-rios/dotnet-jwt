namespace ArturRios.Jwt.Tests;

public class JwtConfigurationTests
{
    [Fact]
    public void Given_NoArguments_When_ConfigurationIsConstructed_Then_DefaultValuesAreSet()
    {
        var configuration = new JwtConfiguration();

        Assert.Equal(0, configuration.ExpirationInSeconds);
        Assert.Equal(string.Empty, configuration.Issuer);
        Assert.Equal(string.Empty, configuration.Audience);
        Assert.Equal(string.Empty, configuration.Secret);
        Assert.Empty(configuration.Claims);
    }

    [Fact]
    public void Given_Arguments_When_ConfigurationIsConstructed_Then_PropertiesAreSetFromArguments()
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
    public void Given_TwoConfigurationsWithSameValues_When_ConfigurationsAreCompared_Then_TheyAreEqual()
    {
        var claims = new Dictionary<string, string> { { "id", "1" } };
        var first = new JwtConfiguration(3600, "issuer", "audience", "secret", claims);
        var second = new JwtConfiguration(3600, "issuer", "audience", "secret", claims);

        var areEqual = first.Equals(second);

        Assert.True(areEqual);
    }

    [Fact]
    public void Given_TwoConfigurationsWithDifferentValues_When_ConfigurationsAreCompared_Then_TheyAreNotEqual()
    {
        var first = new JwtConfiguration(3600, "issuer", "audience", "secret", new Dictionary<string, string>());
        var second = new JwtConfiguration(1800, "other-issuer", "other-audience", "other-secret", new Dictionary<string, string>());

        var areEqual = first.Equals(second);

        Assert.False(areEqual);
    }
}
