using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Time.Testing;

namespace ArturRios.Jwt.Tests;

/// <summary>
/// The clock a <see cref="JwtHandler"/> takes: every "now" it uses, to issue a token and to judge one's lifetime,
/// comes from it.
/// </summary>
[Trait("Category", "Unit")]
public class JwtHandlerClockTests
{
    private const string Secret = "a-secret-that-is-at-least-32-bytes-long!!";

    // Years before any real clock this suite runs under, so a lifetime judged against real time would have ended.
    private static readonly DateTimeOffset Start = new(2020, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private static JwtConfiguration Configuration(double expirationInSeconds = 60) =>
        new(expirationInSeconds, "issuer", "audience", Secret, new Dictionary<string, string> { ["id"] = "1" });

    [Fact]
    public void GivenAFakeClock_WhenATokenIsCreated_ThenItsLifetimeAndIssueTimeComeFromTheClock()
    {
        var handler = new JwtHandler(new FakeTimeProvider(Start));

        var read = new JwtSecurityTokenHandler().ReadJwtToken(handler.CreateToken(Configuration(90)));

        Assert.Equal(Start.UtcDateTime, read.ValidFrom);
        Assert.Equal(Start.UtcDateTime, read.IssuedAt);
        Assert.Equal(Start.UtcDateTime.AddSeconds(90), read.ValidTo);
    }

    [Fact]
    public async Task GivenATokenIssuedByAFakeClockYearsAgo_WhenValidatedByTheSameHandler_ThenItIsAccepted()
    {
        // Real time is years past this token's expiry: it is accepted only if validation reads the same clock.
        var handler = new JwtHandler(new FakeTimeProvider(Start));
        var token = handler.CreateToken(Configuration());

        Assert.True(await handler.IsTokenValidAsync(token, Secret));
        Assert.True(await handler.IsTokenValidAsync(token, [new JwtKey("k1", Secret)]));
        Assert.False(await new JwtHandler().IsTokenValidAsync(token, Secret));
    }

    [Fact]
    public async Task GivenATokenASecondBeforeItExpires_WhenValidated_ThenItIsAccepted()
    {
        var clock = new FakeTimeProvider(Start);
        var handler = new JwtHandler(clock);
        var token = handler.CreateToken(Configuration(60));

        clock.Advance(TimeSpan.FromSeconds(59));

        Assert.True(await handler.IsTokenValidAsync(token, Secret));
    }

    [Fact]
    public async Task GivenATokenASecondAfterItExpired_WhenValidated_ThenItIsRefusedWithNoClockSkew()
    {
        // The library's default skew of five minutes would still accept it.
        var clock = new FakeTimeProvider(Start);
        var handler = new JwtHandler(clock);
        var token = handler.CreateToken(Configuration(60));

        clock.Advance(TimeSpan.FromSeconds(61));

        Assert.False(await handler.IsTokenValidAsync(token, Secret));
        Assert.False(await handler.IsTokenValidAsync(token, [new JwtKey("k1", Secret)]));
    }

    [Fact]
    public async Task GivenAValidatorWhoseClockIsBehindTheIssuers_WhenValidatingBeforeTheTokenStarts_ThenItIsRefused()
    {
        var issuer = new JwtHandler(new FakeTimeProvider(Start));
        var validatorClock = new FakeTimeProvider(Start - TimeSpan.FromSeconds(1));
        var validator = new JwtHandler(validatorClock);
        var token = issuer.CreateToken(Configuration());

        Assert.False(await validator.IsTokenValidAsync(token, Secret));

        validatorClock.Advance(TimeSpan.FromSeconds(1));

        Assert.True(await validator.IsTokenValidAsync(token, Secret));
    }

    [Fact]
    public async Task GivenATokenWithNoStart_WhenValidatedInsideItsExpiry_ThenItIsAccepted()
    {
        var handler = new JwtHandler(new FakeTimeProvider(Start));
        var token = TestTokens.Hs256(Secret, notBefore: null, Start.UtcDateTime.AddMinutes(1));

        Assert.True(await handler.IsTokenValidAsync(token, Secret));
    }

    [Fact]
    public async Task GivenATokenWhoseLifetimeEndsBeforeItStarts_WhenValidatedBetweenTheTwo_ThenItIsRefused()
    {
        var handler = new JwtHandler(new FakeTimeProvider(Start));
        var token = TestTokens.Hs256WithRawLifetime(Secret, Start.UtcDateTime.AddMinutes(1), Start.UtcDateTime.AddMinutes(-1));

        Assert.False(await handler.IsTokenValidAsync(token, Secret));
    }

    [Fact]
    public void GivenTheDefaultConstructor_WhenATokenIsCreated_ThenItsLifetimeStartsAtTheSystemClocksNow()
    {
        var before = DateTime.UtcNow.AddSeconds(-1);

        var read = new JwtSecurityTokenHandler().ReadJwtToken(new JwtHandler().CreateToken(Configuration()));

        Assert.InRange(read.ValidFrom, before, DateTime.UtcNow.AddSeconds(1));
    }

    [Fact]
    public void GivenANullTimeProvider_WhenAHandlerIsConstructed_ThenItThrows()
    {
        Assert.Throws<ArgumentNullException>(() => new JwtHandler(null!));
    }
}
