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

        var issuedAccepting = _handler.CreateToken(accepting);

        Assert.True(await _handler.IsTokenValidAsync(issuedBefore, accepting.Keys));
        Assert.True(await _handler.IsTokenValidAsync(issuedAccepting, accepting.Keys));
        Assert.Equal(OldKey.Id, _handler.GetKeyIdFromToken(issuedAccepting));

        // Step 2: the new key starts signing. Tokens issued under the old one still validate.
        var rotated = Configuration([OldKey, NewKey], NewKey.Id);

        _validator.ValidateAndThrow(rotated);

        var issuedAfter = _handler.CreateToken(rotated);

        Assert.Equal(NewKey.Id, _handler.GetKeyIdFromToken(issuedAfter));
        Assert.True(await _handler.IsTokenValidAsync(issuedBefore, rotated.Keys));
        Assert.True(await _handler.IsTokenValidAsync(issuedAccepting, rotated.Keys));
        Assert.True(await _handler.IsTokenValidAsync(issuedAfter, rotated.Keys));

        // Step 3: the old key is withdrawn once nothing it signed can still be alive.
        var withdrawn = Configuration([NewKey], NewKey.Id);

        _validator.ValidateAndThrow(withdrawn);

        Assert.False(await _handler.IsTokenValidAsync(issuedBefore, withdrawn.Keys));
        Assert.False(await _handler.IsTokenValidAsync(issuedAccepting, withdrawn.Keys));
        Assert.True(await _handler.IsTokenValidAsync(issuedAfter, withdrawn.Keys));
    }







}
