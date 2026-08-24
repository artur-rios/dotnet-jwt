using FluentValidation;

namespace ArturRios.Jwt.Tests.Functional;

/// <summary>
/// Walks the three-step rotation the README documents, end to end: configuration validated, tokens issued
/// and validated at every step, and the guarantee that nobody is signed out along the way.
/// </summary>
[Trait("Category", "Functional")]
public class KeyRotationLifecycleTests
{
    private const string OldSecret = "the-old-signing-secret-at-least-32-bytes";
    private const string NewSecret = "the-new-signing-secret-at-least-32-bytes";

    private static readonly JwtKey OldKey = new("2026-01", OldSecret);
    private static readonly JwtKey NewKey = new("2026-08", NewSecret);

    private readonly JwtHandler _handler = new();
    private readonly JwtConfigurationValidator _validator = new();

    private static JwtConfiguration Configuration(IReadOnlyCollection<JwtKey> keys, string? signingKeyId) =>
        new(300, "issuer", "audience", string.Empty, new Dictionary<string, string> { ["id"] = "7" })
        {
            Keys = keys,
            SigningKeyId = signingKeyId
        };

    [Fact]
    public async Task GivenTheDocumentedRotation_WhenWalkedStepByStep_ThenNoIssuedTokenIsEverInvalidated()
    {
        // Step 0: signing with the old key alone.
        var before = Configuration([OldKey], OldKey.Id);

        _validator.ValidateAndThrow(before);

        var issuedBefore = _handler.CreateToken(before);

        Assert.True(await _handler.IsTokenValidAsync(issuedBefore, before.Keys));
        Assert.Equal(OldKey.Id, _handler.GetKeyIdFromToken(issuedBefore));

        // Step 1: the new key is accepted everywhere, but nothing signs with it yet.
        var accepting = Configuration([OldKey, NewKey], OldKey.Id);

        _validator.ValidateAndThrow(accepting);

        Assert.True(await _handler.IsTokenValidAsync(issuedBefore, accepting.Keys));
        Assert.Equal(OldKey.Id, _handler.GetKeyIdFromToken(_handler.CreateToken(accepting)));

        // Step 2: the new key starts signing. Tokens issued under the old one still validate.
        var rotated = Configuration([OldKey, NewKey], NewKey.Id);

        _validator.ValidateAndThrow(rotated);

        var issuedAfter = _handler.CreateToken(rotated);

        Assert.Equal(NewKey.Id, _handler.GetKeyIdFromToken(issuedAfter));
        Assert.True(await _handler.IsTokenValidAsync(issuedBefore, rotated.Keys));
        Assert.True(await _handler.IsTokenValidAsync(issuedAfter, rotated.Keys));

        // Step 3: the old key is withdrawn once nothing it signed can still be alive.
        var withdrawn = Configuration([NewKey], NewKey.Id);

        _validator.ValidateAndThrow(withdrawn);

        Assert.False(await _handler.IsTokenValidAsync(issuedBefore, withdrawn.Keys));
        Assert.True(await _handler.IsTokenValidAsync(issuedAfter, withdrawn.Keys));
    }

    [Fact]
    public async Task GivenATokenIssuedBeforeRotationWasAdopted_WhenValidatedAgainstKeys_ThenItIsStillAccepted()
    {
        var legacy = new JwtConfiguration(300, "issuer", "audience", OldSecret,
            new Dictionary<string, string> { ["id"] = "7" });

        var legacyToken = _handler.CreateToken(legacy);

        Assert.Null(_handler.GetKeyIdFromToken(legacyToken));
        Assert.True(await _handler.IsTokenValidAsync(legacyToken, new[] { NewKey, OldKey }));
    }

    [Fact]
    public async Task GivenATokenNamingAKeyThatIsNotConfigured_WhenValidating_ThenItIsRefusedWithoutTryingTheOthers()
    {
        var strangerKey = new JwtKey("stranger", OldSecret);
        var stranger = Configuration([strangerKey], strangerKey.Id);

        var token = _handler.CreateToken(stranger);

        // Same secret as OldKey, different id: refusing on the id alone is the documented behaviour.
        Assert.False(await _handler.IsTokenValidAsync(token, new[] { OldKey }));
    }

    [Fact]
    public void GivenASigningKeyThatIsNotInKeys_WhenValidatingTheConfiguration_ThenItIsRejected()
    {
        var invalid = Configuration([OldKey], NewKey.Id);

        var errors = _validator.Validate(invalid).Errors;

        Assert.Contains(errors, error => error.PropertyName == nameof(JwtConfiguration.SigningKeyId));
    }

    [Fact]
    public void GivenASigningKeyThatIsNotInKeys_WhenCreatingAToken_ThenItFailsBeforeIssuingOne()
    {
        var invalid = Configuration([OldKey], NewKey.Id);

        Assert.Throws<InvalidOperationException>(() => _handler.CreateToken(invalid));
    }

    [Fact]
    public void GivenTwoKeysSharingAnId_WhenValidatingTheConfiguration_ThenItIsRejected()
    {
        var duplicate = Configuration([OldKey, new JwtKey(OldKey.Id, NewSecret)], OldKey.Id);

        var errors = _validator.Validate(duplicate).Errors;

        Assert.Contains(errors, error => error.PropertyName == nameof(JwtConfiguration.Keys));
    }

    [Fact]
    public void GivenNoKeysAndNoSecret_WhenValidatingTheConfiguration_ThenTheSecretIsRequired()
    {
        var empty = new JwtConfiguration(300, "issuer", "audience", string.Empty,
            new Dictionary<string, string> { ["id"] = "7" });

        var errors = _validator.Validate(empty).Errors;

        Assert.Contains(errors, error => error.PropertyName == nameof(JwtConfiguration.Secret));
    }

    [Fact]
    public void GivenKeysButNoSecret_WhenValidatingTheConfiguration_ThenTheSecretIsNotRequired()
    {
        var errors = _validator.Validate(Configuration([OldKey], OldKey.Id)).Errors;

        Assert.DoesNotContain(errors, error => error.PropertyName == nameof(JwtConfiguration.Secret));
    }
}
