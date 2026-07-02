using FluentValidation.TestHelper;

namespace ArturRios.Jwt.Tests;

public class JwtConfigurationValidatorTests
{
    private readonly JwtConfigurationValidator _validator = new();

    private static JwtConfiguration ValidConfiguration()
    {
        return new JwtConfiguration(3600, "issuer", "audience", "secret", new Dictionary<string, string> { { "id", "1" } });
    }

    [Fact]
    public void Given_ValidConfiguration_When_Validated_Then_HasNoValidationErrors()
    {
        var configuration = ValidConfiguration();

        var result = _validator.TestValidate(configuration);

        result.ShouldNotHaveAnyValidationErrors();
    }

    [Fact]
    public void Given_EmptyAudience_When_Validated_Then_HasValidationErrorForAudience()
    {
        var configuration = ValidConfiguration() with { Audience = string.Empty };

        var result = _validator.TestValidate(configuration);

        result.ShouldHaveValidationErrorFor(config => config.Audience);
    }

    [Fact]
    public void Given_EmptyIssuer_When_Validated_Then_HasValidationErrorForIssuer()
    {
        var configuration = ValidConfiguration() with { Issuer = string.Empty };

        var result = _validator.TestValidate(configuration);

        result.ShouldHaveValidationErrorFor(config => config.Issuer);
    }

    [Fact]
    public void Given_EmptySecret_When_Validated_Then_HasValidationErrorForSecret()
    {
        var configuration = ValidConfiguration() with { Secret = string.Empty };

        var result = _validator.TestValidate(configuration);

        result.ShouldHaveValidationErrorFor(config => config.Secret);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Given_ExpirationInSecondsNotGreaterThanZero_When_Validated_Then_HasValidationErrorForExpirationInSeconds(double expirationInSeconds)
    {
        var configuration = ValidConfiguration() with { ExpirationInSeconds = expirationInSeconds };

        var result = _validator.TestValidate(configuration);

        result.ShouldHaveValidationErrorFor(config => config.ExpirationInSeconds);
    }

    [Fact]
    public void Given_EmptyClaims_When_Validated_Then_HasValidationErrorForClaims()
    {
        var configuration = ValidConfiguration() with { Claims = new Dictionary<string, string>() };

        var result = _validator.TestValidate(configuration);

        result.ShouldHaveValidationErrorFor(config => config.Claims);
    }
}
