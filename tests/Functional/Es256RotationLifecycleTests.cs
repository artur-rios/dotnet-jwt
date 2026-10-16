using FluentValidation;

namespace ArturRios.Jwt.Tests.Functional;

/// <summary>
/// The ES256 rotation a publisher and a consumer walk together: the publisher signs and publishes a key
/// set, the consumer reads it and validates, and the documented three steps sign nobody out.
/// </summary>
[Trait("Category", "Functional")]
public class Es256RotationLifecycleTests
{
    private readonly JwtHandler _handler = new();
    private readonly JwtConfigurationValidator _validator = new();

    private static JwtConfiguration Publisher(JwtKey signingKey, params JwtKey[] alsoPublished) =>
        new(300, "issuer", "audience", string.Empty, new Dictionary<string, string> { ["id"] = "7" })
        {
            Algorithm = JwtAlgorithms.ES256,
            Keys = [signingKey, .. alsoPublished],
            SigningKeyId = signingKey.Id
        };

    /// <summary>What a consumer validates with: the publisher's key set, as published and read back.</summary>
    private static IReadOnlyList<JwtKey> Consumer(JwtConfiguration publisher) =>
        JwksDocument.Parse(JwksDocument.From(publisher.Keys.Select(key => key.ToPublicKey())));

    [Fact]
    public async Task GivenTheDocumentedRotation_WhenWalkedThroughAPublishedKeySet_ThenNoIssuedTokenIsEverInvalidated()
    {
        var oldKey = TestKeys.NewEs256Key();
        var newKey = TestKeys.NewEs256Key();

        // Step 0: the old key signs and is the only one published.
        var before = Publisher(oldKey);
        _validator.ValidateAndThrow(before);
        var issuedBefore = _handler.CreateToken(before);

        Assert.True(await _handler.IsTokenValidAsync(issuedBefore, Consumer(before)));

        // Step 1: the new key signs, and the old one stays published as the previous key.
        var rotated = Publisher(newKey, oldKey.ToPublicKey());
        _validator.ValidateAndThrow(rotated);
        var issuedAfter = _handler.CreateToken(rotated);

        Assert.Equal(newKey.Id, _handler.GetKeyIdFromToken(issuedAfter));
        Assert.True(await _handler.IsTokenValidAsync(issuedBefore, Consumer(rotated)));
        Assert.True(await _handler.IsTokenValidAsync(issuedAfter, Consumer(rotated)));

        // Step 2: after one token lifetime the old key is withdrawn. Only its tokens die, and none is alive.
        var after = Publisher(newKey);
        _validator.ValidateAndThrow(after);

        Assert.True(await _handler.IsTokenValidAsync(issuedAfter, Consumer(after)));
        Assert.False(await _handler.IsTokenValidAsync(issuedBefore, Consumer(after)));
    }
}
