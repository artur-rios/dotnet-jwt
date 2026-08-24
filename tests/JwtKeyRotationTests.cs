namespace ArturRios.Jwt.Tests;

/// <summary>
/// Covers signing with one key while accepting several — what turns replacing a secret from a
/// cutover, where every token in flight dies at once, into a rotation.
/// </summary>
[Trait("Category", "Unit")]
public class JwtKeyRotationTests
{
    private readonly JwtHandler _handler = new();

    private const string OldSecret = "the-previous-signing-key-of-32-bytes+++";
    private const string NewSecret = "the-current-signing-key-with-32-bytes++";
    private const string ForeignSecret = "a-key-this-configuration-never-knew+++";

    private static readonly JwtKey OldKey = new("k1", OldSecret);
    private static readonly JwtKey NewKey = new("k2", NewSecret);

    private static JwtConfiguration Configuration(
        string? signingKeyId = null, params JwtKey[] keys) =>
        new(3600, "issuer", "audience", OldSecret, new Dictionary<string, string> { { "id", "42" } })
        {
            Keys = keys,
            SigningKeyId = signingKeyId
        };

    [Fact]
    public void Given_ASigningKeyId_When_CreateTokenIsCalled_Then_TheTokenNamesTheKeyThatSignedIt()
    {
        var token = _handler.CreateToken(Configuration("k2", OldKey, NewKey));

        Assert.Equal("k2", _handler.GetKeyIdFromToken(token));
    }

    [Fact]
    public void Given_NoSigningKeyId_When_CreateTokenIsCalled_Then_TheTokenCarriesNoKeyId()
    {
        // The shape every configuration had before rotation existed. It must keep producing exactly
        // what it produced then, or adopting the feature would invalidate tokens already issued.
        var token = _handler.CreateToken(Configuration());

        Assert.Null(_handler.GetKeyIdFromToken(token));
    }

    [Fact]
    public async Task Given_ASigningKeyId_When_ValidatedAgainstThatKey_Then_ItIsValid()
    {
        var token = _handler.CreateToken(Configuration("k2", OldKey, NewKey));

        Assert.True(await _handler.IsTokenValidAsync(token, [OldKey, NewKey]));
    }

    [Fact]
    public async Task Given_ATokenSignedWithTheRetiredKey_When_ThatKeyIsStillAccepted_Then_ItIsValid()
    {
        // The whole point. A token issued before the rotation keeps working while its key remains in
        // the accepted set, so switching signing keys does not sign everyone out.
        var issuedBefore = _handler.CreateToken(Configuration("k1", OldKey, NewKey));

        Assert.True(await _handler.IsTokenValidAsync(issuedBefore, [OldKey, NewKey]));
    }

    [Fact]
    public async Task Given_ATokenSignedWithAWithdrawnKey_When_Validated_Then_ItIsRefused()
    {
        // The other half, and the one that matters when a key has leaked rather than merely aged:
        // dropping it from the accepted set must invalidate its tokens at once.
        var issuedBefore = _handler.CreateToken(Configuration("k1", OldKey, NewKey));

        Assert.False(await _handler.IsTokenValidAsync(issuedBefore, [NewKey]));
    }

    [Fact]
    public async Task Given_ATokenWithAnUnknownKeyId_When_Validated_Then_ItIsRefused()
    {
        // The kid names a key nothing here accepts, so the answer is already decided; the other keys
        // are not tried.
        var foreign = new JwtKey("k9", ForeignSecret);
        var token = _handler.CreateToken(Configuration("k9", foreign));

        Assert.False(await _handler.IsTokenValidAsync(token, [OldKey, NewKey]));
    }

    [Fact]
    public async Task Given_ATokenClaimingOneKeyButSignedWithAnother_When_Validated_Then_ItIsRefused()
    {
        // The kid selects a key. It never grants anything, so a token that names a key it was not
        // signed with is refused rather than checked against whatever else might match.
        var mislabelled = _handler.CreateToken(Configuration("k2", new JwtKey("k2", ForeignSecret)));

        Assert.False(await _handler.IsTokenValidAsync(mislabelled, [OldKey, NewKey]));
    }

    [Fact]
    public async Task Given_ATokenWithNoKeyId_When_ValidatedAgainstAKeySet_Then_EveryKeyIsTried()
    {
        // Tokens issued before the deployment adopted rotation carry no kid. They have to keep
        // validating, or turning the feature on would be the outage it exists to prevent.
        var legacy = _handler.CreateToken(Configuration());

        Assert.True(await _handler.IsTokenValidAsync(legacy, [NewKey, OldKey]));
    }

    [Fact]
    public async Task Given_ATokenWithNoKeyIdSignedByNothingInTheSet_When_Validated_Then_ItIsRefused()
    {
        var configuration = Configuration() with { Secret = ForeignSecret };
        var token = _handler.CreateToken(configuration);

        Assert.False(await _handler.IsTokenValidAsync(token, [OldKey, NewKey]));
    }

    [Fact]
    public async Task Given_AnEmptyKeySet_When_Validated_Then_ItIsRefused()
    {
        // Nothing is accepted rather than everything: an empty set is a configuration mistake, and
        // the safe reading of it is that no signature satisfies it.
        var token = _handler.CreateToken(Configuration("k2", OldKey, NewKey));

        Assert.False(await _handler.IsTokenValidAsync(token, []));
    }

    [Fact]
    public async Task Given_AnExpiredToken_When_ValidatedAgainstItsKey_Then_ItIsRefused()
    {
        // Naming the right key does not excuse a token from expiring.
        var configuration = Configuration("k2", OldKey, NewKey) with { ExpirationInSeconds = 1 };
        var token = _handler.CreateToken(configuration);

        await Task.Delay(TimeSpan.FromSeconds(2));

        Assert.False(await _handler.IsTokenValidAsync(token, [OldKey, NewKey]));
    }

    [Fact]
    public void Given_ASigningKeyIdNamingNoKey_When_CreateTokenIsCalled_Then_ItThrows()
    {
        // Signing with a key nothing accepts would produce tokens that fail on first use, far from
        // the configuration that caused it.
        var configuration = Configuration("k3", OldKey, NewKey);

        var failure = Assert.Throws<InvalidOperationException>(() => _handler.CreateToken(configuration));

        Assert.Contains("k3", failure.Message);
    }

    [Fact]
    public async Task Given_AKeyIdIsAddedWithoutChangingTheSecret_When_ValidatedTheOldWay_Then_ItIsStillValid()
    {
        // The single-key overload knows nothing about kid, and must keep working against a token that
        // now carries one — otherwise adopting rotation would break every consumer still calling it.
        var token = _handler.CreateToken(Configuration("k2", NewKey));

        Assert.True(await _handler.IsTokenValidAsync(token, NewSecret));
    }

    [Fact]
    public async Task Given_TheDocumentedRotation_When_ItIsPerformedInOrder_Then_NoTokenIsEverRefused()
    {
        // The procedure end to end: add the new key, switch signing to it, then withdraw the old one.
        // A token issued at each step is checked at every later step, which is what "no one is signed
        // out" has to mean.
        var beforeAnything = _handler.CreateToken(Configuration("k1", OldKey));

        // Step 1 — the new key is accepted everywhere, but nothing signs with it yet.
        var accepting = new[] { OldKey, NewKey };
        var duringStepOne = _handler.CreateToken(Configuration("k1", accepting));

        Assert.True(await _handler.IsTokenValidAsync(beforeAnything, accepting));
        Assert.True(await _handler.IsTokenValidAsync(duringStepOne, accepting));

        // Step 2 — signing switches to the new key. Both are still accepted.
        var duringStepTwo = _handler.CreateToken(Configuration("k2", accepting));

        Assert.True(await _handler.IsTokenValidAsync(beforeAnything, accepting));
        Assert.True(await _handler.IsTokenValidAsync(duringStepOne, accepting));
        Assert.True(await _handler.IsTokenValidAsync(duringStepTwo, accepting));

        // Step 3 — after one token lifetime, the old key is withdrawn. Only tokens it signed die, and
        // by then none of them is still alive.
        Assert.True(await _handler.IsTokenValidAsync(duringStepTwo, [NewKey]));
        Assert.False(await _handler.IsTokenValidAsync(beforeAnything, [NewKey]));
    }
}
