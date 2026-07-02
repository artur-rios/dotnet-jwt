namespace ArturRios.Jwt.Tests;

public class JwtHandlerTests
{
    private readonly JwtHandler _handler = new();

    private const string ValidSecret = "super-secret-signing-key-with-32-bytes+";

    private static JwtConfiguration ValidConfiguration(Dictionary<string, string>? claims = null, double expirationInSeconds = 3600)
    {
        return new JwtConfiguration(expirationInSeconds, "issuer", "audience", ValidSecret, claims ?? new Dictionary<string, string> { { "id", "42" } });
    }

    [Fact]
    public void Given_ValidConfiguration_When_CreateTokenIsCalled_Then_ReturnsWellFormedJwt()
    {
        var configuration = ValidConfiguration();

        var token = _handler.CreateToken(configuration);

        Assert.False(string.IsNullOrWhiteSpace(token));
        Assert.Equal(3, token.Split('.').Length);
    }

    [Fact]
    public void Given_TokenWithIdClaim_When_GetUserIdFromTokenIsCalled_Then_ReturnsClaimId()
    {
        var configuration = ValidConfiguration(new Dictionary<string, string> { { "id", "42" } });
        var token = _handler.CreateToken(configuration);

        var userId = _handler.GetUserIdFromToken(token);

        Assert.Equal(42, userId);
    }

    [Fact]
    public void Given_UnreadableToken_When_GetUserIdFromTokenIsCalled_Then_ReturnsNull()
    {
        const string token = "not-a-valid-jwt";

        var userId = _handler.GetUserIdFromToken(token);

        Assert.Null(userId);
    }

    [Fact]
    public async Task Given_ValidTokenAndMatchingSecret_When_IsTokenValidAsyncIsCalled_Then_ReturnsTrue()
    {
        var configuration = ValidConfiguration();
        var token = _handler.CreateToken(configuration);

        var isValid = await _handler.IsTokenValidAsync(token, ValidSecret);

        Assert.True(isValid);
    }

    [Fact]
    public async Task Given_ValidTokenAndWrongSecret_When_IsTokenValidAsyncIsCalled_Then_ReturnsFalse()
    {
        var configuration = ValidConfiguration();
        var token = _handler.CreateToken(configuration);

        var isValid = await _handler.IsTokenValidAsync(token, "a-completely-different-secret-with-32-bytes+");

        Assert.False(isValid);
    }

    [Fact]
    public async Task Given_ExpiredToken_When_IsTokenValidAsyncIsCalled_Then_ReturnsFalse()
    {
        var configuration = ValidConfiguration(expirationInSeconds: 1);
        var token = _handler.CreateToken(configuration);
        await Task.Delay(TimeSpan.FromSeconds(2));

        var isValid = await _handler.IsTokenValidAsync(token, ValidSecret);

        Assert.False(isValid);
    }
}
