using FluentValidation.TestHelper;

namespace ArturRios.Jwt.Tests;

[Trait("Category", "Unit")]
public class JwtConfigurationValidatorTests
{
    private readonly JwtConfigurationValidator _validator = new();

    private static JwtConfiguration ValidConfiguration()
    {
        return new JwtConfiguration(3600, "issuer", "audience", "a-secret-that-is-at-least-32-bytes-long", new Dictionary<string, string> { { "id", "1" } });
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
    public void Given_KeysButNeitherASigningKeyIdNorASecret_When_Validated_Then_HasValidationErrorForSecret()
    {
        // Without a SigningKeyId, CreateToken signs with Secret, so a blank one is a configuration
        // that cannot issue a token. It used to pass validation and throw on the first CreateToken.
        var configuration = ValidConfiguration() with
        {
            Secret = string.Empty,
            Keys = [new JwtKey("k1", "the-current-signing-key-with-32-bytes++")]
        };

        var result = _validator.TestValidate(configuration);

        result.ShouldHaveValidationErrorFor(config => config.Secret);
    }

    [Fact]
    public void Given_KeysAndASigningSecretThatIsNotOneOfThem_When_Validated_Then_HasValidationErrorForSecret()
    {
        // The tokens would be signed with a key the configured key set does not accept, so every one
        // of them would fail validation against Keys — the same mistake SigningKeyId is guarded against.
        var configuration = ValidConfiguration() with
        {
            Keys = [new JwtKey("k1", "the-current-signing-key-with-32-bytes++")]
        };

        var result = _validator.TestValidate(configuration);

        result.ShouldHaveValidationErrorFor(config => config.Secret);
    }

    [Fact]
    public void Given_KeysAndASigningSecretThatIsOneOfThem_When_Validated_Then_HasNoValidationErrors()
    {
        // A deployment adopting rotation: still signing with its old secret, which is now also a key.
        var configuration = ValidConfiguration() with
        {
            Keys =
            [
                new JwtKey("old", ValidConfiguration().Secret),
                new JwtKey("new", "the-current-signing-key-with-32-bytes++")
            ]
        };

        var result = _validator.TestValidate(configuration);

        result.ShouldNotHaveAnyValidationErrors();
    }

    [Fact]
    public void Given_ASecretShorterThan32Bytes_When_Validated_Then_HasValidationErrorForSecret()
    {
        // HMAC-SHA256 needs a 256-bit key (RFC 7518 3.2), and the handler refuses to sign with a
        // short one at all, so such a configuration used to pass here and fail in CreateToken.
        var configuration = ValidConfiguration() with { Secret = new string('s', 31) };

        var result = _validator.TestValidate(configuration);

        result.ShouldHaveValidationErrorFor(config => config.Secret);
    }

    [Fact]
    public void Given_ASecretOfExactly32Bytes_When_Validated_Then_HasNoValidationErrors()
    {
        var result = _validator.TestValidate(ValidConfiguration() with { Secret = new string('s', 32) });

        result.ShouldNotHaveAnyValidationErrors();
    }

    [Fact]
    public void Given_AShortSecretThatSignsNothing_When_Validated_Then_ItIsNotChecked()
    {
        // With a SigningKeyId the secret is unused, so its length is irrelevant.
        var configuration = ValidConfiguration() with
        {
            Secret = "short",
            Keys = [new JwtKey("k1", "the-current-signing-key-with-32-bytes++")],
            SigningKeyId = "k1"
        };

        var result = _validator.TestValidate(configuration);

        result.ShouldNotHaveValidationErrorFor(config => config.Secret);
    }

    [Fact]
    public void Given_AKeyWithASecretShorterThan32Bytes_When_Validated_Then_HasValidationErrorForKeys()
    {
        var configuration = ValidConfiguration() with
        {
            Keys = [new JwtKey("k1", "the-current-signing-key-with-32-bytes++"), new JwtKey("k2", "too-short")],
            SigningKeyId = "k1"
        };

        var result = _validator.TestValidate(configuration);

        result.ShouldHaveValidationErrorFor(config => config.Keys);
    }

    [Fact]
    public void Given_AConfigurationThatPassesValidation_When_CreatingAToken_Then_ItDoesNotThrow()
    {
        // The validator's stated purpose: a configuration it accepts is one that can create a token.
        var handler = new JwtHandler();

        foreach (var configuration in new[]
                 {
                     ValidConfiguration(),
                     ValidConfiguration() with { Secret = new string('s', 32) },
                     ValidConfiguration() with
                     {
                         Secret = string.Empty,
                         Keys = [new JwtKey("k1", "the-current-signing-key-with-32-bytes++")],
                         SigningKeyId = "k1"
                     }
                 })
        {
            _validator.TestValidate(configuration).ShouldNotHaveAnyValidationErrors();

            Assert.False(string.IsNullOrWhiteSpace(handler.CreateToken(configuration)));
        }
    }

    [Fact]
    public void Given_NoSigningKeyIdAndNoKeys_When_Validated_Then_HasNoValidationErrors()
    {
        // The shape every configuration had before rotation existed stays valid, unchanged.
        var result = _validator.TestValidate(ValidConfiguration());

        result.ShouldNotHaveAnyValidationErrors();
    }

    [Fact]
    public void Given_AConfigurationWithNoAlgorithmSet_When_Inspected_Then_ItIsHs256()
    {
        Assert.Equal(JwtAlgorithms.HS256, ValidConfiguration().Algorithm);
    }

    [Fact]
    public void Given_AValidEs256Configuration_When_Validated_Then_HasNoValidationErrors()
    {
        _validator.TestValidate(TestKeys.Es256Configuration()).ShouldNotHaveAnyValidationErrors();
    }

    [Fact]
    public void Given_AnEs256ConfigurationAcceptingAPreviousPublicKey_When_Validated_Then_HasNoValidationErrors()
    {
        var current = TestKeys.NewEs256Key();
        var configuration = TestKeys.Es256Configuration(current) with { Keys = [current, TestKeys.NewEs256Key().ToPublicKey()] };

        _validator.TestValidate(configuration).ShouldNotHaveAnyValidationErrors();
    }

    [Fact]
    public void Given_AnUnknownAlgorithm_When_Validated_Then_HasValidationErrorForAlgorithm()
    {
        var result = _validator.TestValidate(ValidConfiguration() with { Algorithm = "RS256" });

        result.ShouldHaveValidationErrorFor(config => config.Algorithm);
    }

    [Fact]
    public void Given_AnEs256ConfigurationWithASecret_When_Validated_Then_HasValidationErrorForSecret()
    {
        // ES256 signs with the private key in Keys; a secret beside it would be unused, and a reader of
        // the configuration could believe it mattered.
        var result = _validator.TestValidate(TestKeys.Es256Configuration() with { Secret = "a-secret-that-is-at-least-32-bytes-long" });

        result.ShouldHaveValidationErrorFor(config => config.Secret).WithErrorMessage("'Secret' must be empty in an ES256 configuration, which signs with a private key from 'Keys'.");
    }

    [Fact]
    public void Given_AnEs256ConfigurationWithoutASigningKeyId_When_Validated_Then_HasValidationErrorForSigningKeyId()
    {
        var result = _validator.TestValidate(TestKeys.Es256Configuration() with { SigningKeyId = null });

        result.ShouldHaveValidationErrorFor(config => config.SigningKeyId).WithErrorMessage("An ES256 configuration signs with the key 'SigningKeyId' names, so it is required.");
    }

    [Fact]
    public void Given_AnEs256ConfigurationHoldingASecretKey_When_Validated_Then_HasValidationErrorForKeys()
    {
        var current = TestKeys.NewEs256Key();
        var configuration = TestKeys.Es256Configuration(current) with
        {
            Keys = [current, new JwtKey("k1", TestKeys.Secret)]
        };

        _validator.TestValidate(configuration).ShouldHaveValidationErrorFor(config => config.Keys).WithErrorMessage("An ES256 configuration accepts only ES256 keys: every key in 'Keys' must be an EC P-256 key.");
    }

    [Fact]
    public void Given_AnHs256ConfigurationHoldingAnEcKey_When_Validated_Then_HasValidationErrorForKeys()
    {
        // One configuration, one algorithm: an EC key here would either be ignored or be checked against
        // HS256 tokens, and neither is something a reader of the configuration could predict.
        var configuration = ValidConfiguration() with
        {
            Keys = [new JwtKey("k1", ValidConfiguration().Secret), TestKeys.NewEs256Key()]
        };

        _validator.TestValidate(configuration).ShouldHaveValidationErrorFor(config => config.Keys).WithErrorMessage("An HS256 configuration accepts only HS256 keys, but 'Keys' holds an ES256 key. Set 'Algorithm' to ES256, or keep the two kinds of key in separate configurations.");
    }

    [Fact]
    public void Given_AnEs256SigningKeyWithoutItsPrivateHalf_When_Validated_Then_HasValidationErrorForSigningKeyId()
    {
        var result = _validator.TestValidate(TestKeys.Es256Configuration(TestKeys.NewEs256Key().ToPublicKey()));

        result.ShouldHaveValidationErrorFor(config => config.SigningKeyId).WithErrorMessage("The key 'SigningKeyId' names must hold its private half: a public key validates tokens but cannot sign them.");
    }

    [Fact]
    public void Given_AnEs256KeyRenamedAwayFromItsThumbprint_When_Validated_Then_HasValidationErrorForKeys()
    {
        // The kid is derived, never configured: a renamed key would sign tokens no published key set names.
        var renamed = TestKeys.NewEs256Key() with { Id = "current" };

        _validator.TestValidate(TestKeys.Es256Configuration(renamed)).ShouldHaveValidationErrorFor(config => config.Keys).WithErrorMessage("Every ES256 key in 'Keys' must have its RFC 7638 thumbprint as its id.");
    }

    [Fact]
    public void Given_AnEs256ConfigurationThatPassesValidation_When_CreatingAToken_Then_ItDoesNotThrow()
    {
        var configuration = TestKeys.Es256Configuration();

        _validator.TestValidate(configuration).ShouldNotHaveAnyValidationErrors();

        Assert.False(string.IsNullOrWhiteSpace(new JwtHandler().CreateToken(configuration)));
    }
}
