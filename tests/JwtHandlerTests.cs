namespace ArturRios.Jwt.Tests;

[Trait("Category", "Unit")]
public class JwtHandlerTests
{
    private readonly JwtHandler _handler = new();

    private const string ValidSecret = "super-secret-signing-key-with-32-bytes+";

    private static JwtConfiguration ValidConfiguration(Dictionary<string, string>? claims = null, double expirationInSeconds = 3600)
    {
        return new JwtConfiguration(expirationInSeconds, "issuer", "audience", ValidSecret, claims ?? new Dictionary<string, string> { { "id", "42" } });
    }

    [Fact]
    public void GivenValidConfiguration_WhenCreateTokenIsCalled_ThenReturnsWellFormedJwt()
    {
        var configuration = ValidConfiguration();

        var token = _handler.CreateToken(configuration);

        Assert.False(string.IsNullOrWhiteSpace(token));
        Assert.Equal(3, token.Split('.').Length);
    }

    [Fact]
    public void GivenTokenWithIdClaim_WhenGetUserIdFromTokenIsCalled_ThenReturnsClaimId()
    {
        var configuration = ValidConfiguration(new Dictionary<string, string> { { "id", "42" } });
        var token = _handler.CreateToken(configuration);

        var userId = _handler.GetUserIdFromToken(token);

        Assert.Equal(42, userId);
    }

    [Fact]
    public void GivenUnreadableToken_WhenGetUserIdFromTokenIsCalled_ThenReturnsNull()
    {
        const string token = "not-a-valid-jwt";

        var userId = _handler.GetUserIdFromToken(token);

        Assert.Null(userId);
    }

    [Fact]
    public async Task GivenValidTokenAndMatchingSecret_WhenIsTokenValidAsyncIsCalled_ThenReturnsTrue()
    {
        var configuration = ValidConfiguration();
        var token = _handler.CreateToken(configuration);

        var isValid = await _handler.IsTokenValidAsync(token, ValidSecret);

        Assert.True(isValid);
    }

    [Fact]
    public async Task GivenValidTokenAndWrongSecret_WhenIsTokenValidAsyncIsCalled_ThenReturnsFalse()
    {
        var configuration = ValidConfiguration();
        var token = _handler.CreateToken(configuration);

        var isValid = await _handler.IsTokenValidAsync(token, "a-completely-different-secret-with-32-bytes+");

        Assert.False(isValid);
    }

    [Fact]
    public async Task GivenATokenThatExpiredTwoSecondsAgo_WhenIsTokenValidAsyncIsCalled_ThenReturnsFalse()
    {
        // No clock skew is allowed: the library's default of five minutes would still accept it.
        var (notBefore, expires) = TestTokens.EndedAgo(TimeSpan.FromSeconds(2));
        var token = TestTokens.Hs256(ValidSecret, notBefore, expires);

        var isValid = await _handler.IsTokenValidAsync(token, ValidSecret);

        Assert.False(isValid);
    }

    [Fact]
    public async Task GivenATokenWhoseLifetimeStartsInAMinute_WhenIsTokenValidAsyncIsCalled_ThenReturnsFalse()
    {
        var token = TestTokens.Hs256(ValidSecret, DateTime.UtcNow.AddMinutes(1), DateTime.UtcNow.AddHours(1));

        Assert.False(await _handler.IsTokenValidAsync(token, ValidSecret));
        Assert.False(await _handler.IsTokenValidAsync(token, [new JwtKey("k1", ValidSecret)]));
    }

    [Fact]
    public async Task GivenATokenWithNoExpiry_WhenIsTokenValidAsyncIsCalled_ThenReturnsFalse()
    {
        var token = TestTokens.Hs256(ValidSecret, DateTime.UtcNow.AddMinutes(-1), expires: null);

        Assert.False(await _handler.IsTokenValidAsync(token, ValidSecret));
    }

    [Fact]
    public async Task GivenATokenInsideItsLifetime_WhenIsTokenValidAsyncIsCalled_ThenReturnsTrue()
    {
        var token = TestTokens.Hs256(ValidSecret, DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddMinutes(1));

        Assert.True(await _handler.IsTokenValidAsync(token, ValidSecret));
    }
}
