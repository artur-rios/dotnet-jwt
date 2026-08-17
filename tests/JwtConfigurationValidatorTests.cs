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

    [Fact]
    public void Given_KeysButNoSecret_When_Validated_Then_HasNoValidationErrors()
    {
        // Secret was unconditionally required before Keys existed. A configuration that supplies its
        // key material through Keys has no use for it, and should not have to invent one.
        var configuration = ValidConfiguration() with
        {
            Secret = string.Empty,
            Keys = [new JwtKey("k1", "the-current-signing-key-with-32-bytes++")],
            SigningKeyId = "k1"
        };

        var result = _validator.TestValidate(configuration);

        result.ShouldNotHaveAnyValidationErrors();
    }

    [Fact]
    public void Given_NoKeysAndNoSecret_When_Validated_Then_HasValidationErrorForSecret()
    {
        var configuration = ValidConfiguration() with { Secret = string.Empty };

        var result = _validator.TestValidate(configuration);

        result.ShouldHaveValidationErrorFor(config => config.Secret);
    }

    [Fact]
    public void Given_TwoKeysWithTheSameId_When_Validated_Then_HasValidationErrorForKeys()
    {
        // A duplicate id makes the kid header ambiguous, so which key validates a token would come
        // down to configuration ordering.
        var configuration = ValidConfiguration() with
        {
            Keys = [new JwtKey("k1", "the-first-signing-key-with-32-bytes+++"), new JwtKey("k1", "the-second-signing-key-with-32-bytes++")]
        };

        var result = _validator.TestValidate(configuration);

        result.ShouldHaveValidationErrorFor(config => config.Keys);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void Given_AKeyWithoutAnId_When_Validated_Then_HasValidationErrorForKeys(string id)
    {
        var configuration = ValidConfiguration() with
        {
            Keys = [new JwtKey(id, "the-current-signing-key-with-32-bytes++")]
        };

        var result = _validator.TestValidate(configuration);

        result.ShouldHaveValidationErrorFor(config => config.Keys);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void Given_AKeyWithoutASecret_When_Validated_Then_HasValidationErrorForKeys(string secret)
    {
        var configuration = ValidConfiguration() with { Keys = [new JwtKey("k1", secret)] };

        var result = _validator.TestValidate(configuration);

        result.ShouldHaveValidationErrorFor(config => config.Keys);
    }

    [Fact]
    public void Given_ASigningKeyIdNamingNoKey_When_Validated_Then_HasValidationErrorForSigningKeyId()
    {
        // This rule is what makes the documented rotation order safe: the new key must already be
        // accepted everywhere before anything signs with it.
        var configuration = ValidConfiguration() with
        {
            Keys = [new JwtKey("k1", "the-current-signing-key-with-32-bytes++")],
            SigningKeyId = "k2"
        };

        var result = _validator.TestValidate(configuration);

        result.ShouldHaveValidationErrorFor(config => config.SigningKeyId);
    }

    [Fact]
    public void Given_NoSigningKeyIdAndNoKeys_When_Validated_Then_HasNoValidationErrors()
    {
        // The shape every configuration had before rotation existed stays valid, unchanged.
        var result = _validator.TestValidate(ValidConfiguration());

        result.ShouldNotHaveAnyValidationErrors();
    }
}
