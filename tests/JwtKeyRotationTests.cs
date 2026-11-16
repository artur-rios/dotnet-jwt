using Microsoft.Extensions.Time.Testing;

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
    public void GivenASigningKeyId_WhenCreateTokenIsCalled_ThenTheTokenNamesTheKeyThatSignedIt()
    {
        var token = _handler.CreateToken(Configuration("k2", OldKey, NewKey));

        Assert.Equal("k2", _handler.GetKeyIdFromToken(token));
    }

    [Fact]
    public void GivenNoSigningKeyId_WhenCreateTokenIsCalled_ThenTheTokenCarriesNoKeyId()
    {
        // The shape every configuration had before rotation existed. It must keep producing exactly
        // what it produced then, or adopting the feature would invalidate tokens already issued.
        var token = _handler.CreateToken(Configuration());

        Assert.Null(_handler.GetKeyIdFromToken(token));
    }

    [Fact]
    public async Task GivenASigningKeyId_WhenValidatedAgainstThatKey_ThenItIsValid()
    {
        var token = _handler.CreateToken(Configuration("k2", OldKey, NewKey));

        Assert.True(await _handler.IsTokenValidAsync(token, [OldKey, NewKey]));
    }

    [Fact]
    public async Task GivenATokenSignedWithTheRetiredKey_WhenThatKeyIsStillAccepted_ThenItIsValid()
    {
        // The whole point. A token issued before the rotation keeps working while its key remains in
        // the accepted set, so switching signing keys does not sign everyone out.
        var issuedBefore = _handler.CreateToken(Configuration("k1", OldKey, NewKey));

        Assert.True(await _handler.IsTokenValidAsync(issuedBefore, [OldKey, NewKey]));
    }

    [Fact]
    public async Task GivenATokenSignedWithAWithdrawnKey_WhenValidated_ThenItIsRefused()
    {
        // The other half, and the one that matters when a key has leaked rather than merely aged:
        // dropping it from the accepted set must invalidate its tokens at once.
        var issuedBefore = _handler.CreateToken(Configuration("k1", OldKey, NewKey));

        Assert.False(await _handler.IsTokenValidAsync(issuedBefore, [NewKey]));
    }

    [Fact]
    public async Task GivenATokenWithAnUnknownKeyId_WhenValidated_ThenItIsRefused()
    {
        // The kid names a key nothing here accepts, so the answer is already decided; the other keys
        // are not tried.
        var foreign = new JwtKey("k9", ForeignSecret);
        var token = _handler.CreateToken(Configuration("k9", foreign));

        Assert.False(await _handler.IsTokenValidAsync(token, [OldKey, NewKey]));
    }

    [Fact]
    public async Task GivenATokenNamingAnUnknownKeyButSignedWithAnAcceptedSecret_WhenValidated_ThenItIsRefusedOnTheIdAlone()
    {
        // Same secret as OldKey, different id: the unknown kid decides, and the matching secret is never tried.
        var stranger = new JwtKey("stranger", OldSecret);
        var token = _handler.CreateToken(Configuration(stranger.Id, stranger));

        Assert.False(await _handler.IsTokenValidAsync(token, [OldKey]));
    }

    [Fact]
    public async Task GivenATokenClaimingOneKeyButSignedWithAnother_WhenValidated_ThenItIsRefused()
    {
        // The kid selects a key. It never grants anything, so a token that names a key it was not
        // signed with is refused rather than checked against whatever else might match.
        var mislabelled = _handler.CreateToken(Configuration("k2", new JwtKey("k2", ForeignSecret)));

        Assert.False(await _handler.IsTokenValidAsync(mislabelled, [OldKey, NewKey]));
    }

    [Fact]
    public async Task GivenATokenWithNoKeyId_WhenValidatedAgainstAKeySet_ThenEveryKeyIsTried()
    {
        // Tokens issued before the deployment adopted rotation carry no kid. They have to keep
        // validating, or turning the feature on would be the outage it exists to prevent.
        var legacy = _handler.CreateToken(Configuration());

        Assert.True(await _handler.IsTokenValidAsync(legacy, [NewKey, OldKey]));
    }

    [Fact]
    public async Task GivenATokenWithNoKeyIdSignedByNothingInTheSet_WhenValidated_ThenItIsRefused()
    {
        var configuration = Configuration() with { Secret = ForeignSecret };
        var token = _handler.CreateToken(configuration);

        Assert.False(await _handler.IsTokenValidAsync(token, [OldKey, NewKey]));
    }

    [Fact]
    public async Task GivenAnEmptyKeySet_WhenValidated_ThenItIsRefused()
    {
        // Nothing is accepted rather than everything: an empty set is a configuration mistake, and
        // the safe reading of it is that no signature satisfies it.
        var token = _handler.CreateToken(Configuration("k2", OldKey, NewKey));

        Assert.False(await _handler.IsTokenValidAsync(token, []));
    }

    [Fact]
    public async Task GivenAnExpiredToken_WhenValidatedAgainstItsKey_ThenItIsRefused()
    {
        // Naming the right key does not excuse a token from expiring.
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        var handler = new JwtHandler(clock);
        var token = handler.CreateToken(Configuration("k2", OldKey, NewKey) with { ExpirationInSeconds = 60 });

        Assert.Equal(NewKey.Id, handler.GetKeyIdFromToken(token));
        Assert.True(await handler.IsTokenValidAsync(token, [OldKey, NewKey]));

        clock.Advance(TimeSpan.FromSeconds(62));

        Assert.False(await handler.IsTokenValidAsync(token, [OldKey, NewKey]));
    }

    [Fact]
    public void GivenASigningKeyIdNamingNoKey_WhenCreateTokenIsCalled_ThenItThrows()
    {
        // Signing with a key nothing accepts would produce tokens that fail on first use, far from
        // the configuration that caused it.
        var configuration = Configuration("k3", OldKey, NewKey);

        var failure = Assert.Throws<InvalidOperationException>(() => _handler.CreateToken(configuration));

        Assert.Contains("k3", failure.Message);
    }

    [Fact]
    public async Task GivenAKeyIdIsAddedWithoutChangingTheSecret_WhenValidatedTheOldWay_ThenItIsStillValid()
    {
        // The single-key overload knows nothing about kid, and must keep working against a token that
        // now carries one — otherwise adopting rotation would break every consumer still calling it.
        var token = _handler.CreateToken(Configuration("k2", NewKey));

        Assert.True(await _handler.IsTokenValidAsync(token, NewSecret));
    }

}
