using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace ArturRios.Jwt.Tests;

/// <summary>
/// Edge cases around reading claims out of a token and around what validation does and does not check.
/// </summary>
[Trait("Category", "Unit")]
public class JwtHandlerEdgeCaseTests
{
    private const string Secret = "a-secret-that-is-at-least-32-bytes-long!!";

    private readonly JwtHandler _handler = new();

    private static JwtConfiguration Configuration(Dictionary<string, string> claims, double expirationInSeconds = 300) =>
        new(expirationInSeconds, "issuer", "audience", Secret, claims);

    [Fact]
    public void GivenATokenWithoutAnIdClaim_WhenReadingTheUserId_ThenNullComesBack()
    {
        var token = _handler.CreateToken(Configuration(new Dictionary<string, string> { ["name"] = "Ada" }));

        Assert.Null(_handler.GetUserIdFromToken(token));
    }

    [Fact]
    public void GivenATokenWhoseIdClaimIsNotAnInteger_WhenReadingTheUserId_ThenNullComesBack()
    {
        var token = _handler.CreateToken(Configuration(new Dictionary<string, string> { ["id"] = "not-a-number" }));

        Assert.Null(_handler.GetUserIdFromToken(token));
    }

    [Fact]
    public void GivenATokenWhoseIdClaimOverflowsAnInt_WhenReadingTheUserId_ThenNullComesBack()
    {
        var token = _handler.CreateToken(Configuration(new Dictionary<string, string> { ["id"] = "99999999999999999999" }));

        Assert.Null(_handler.GetUserIdFromToken(token));
    }

    [Fact]
    public void GivenATokenWithAnIntegerIdClaim_WhenReadingTheUserId_ThenItComesBack()
    {
        var token = _handler.CreateToken(Configuration(new Dictionary<string, string> { ["id"] = "42" }));

        Assert.Equal(42, _handler.GetUserIdFromToken(token));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-token")]
    [InlineData("a.b.c")]
    [InlineData("...")]
    public void GivenSomethingThatIsNotAToken_WhenReadingTheUserId_ThenNullComesBack(string token)
    {
        Assert.Null(_handler.GetUserIdFromToken(token));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-token")]
    [InlineData("a.b.c")]
    [InlineData("...")]
    public void GivenSomethingThatIsNotAToken_WhenReadingTheKeyId_ThenNullComesBack(string token)
    {
        Assert.Null(_handler.GetKeyIdFromToken(token));
    }

    [Fact]
    public async Task GivenAnExpiredToken_WhenValidating_ThenItIsRejected()
    {
        var token = CreateTokenExpiringAt(DateTime.UtcNow.AddMinutes(-5));

        Assert.False(await _handler.IsTokenValidAsync(token, Secret));
    }

    [Fact]
    public async Task GivenATokenSignedWithADifferentSecret_WhenValidating_ThenItIsRejected()
    {
        var token = _handler.CreateToken(Configuration(new Dictionary<string, string> { ["id"] = "1" }));

        Assert.False(await _handler.IsTokenValidAsync(token, "a-completely-different-secret-32-bytes!!!"));
    }

    [Fact]
    public async Task GivenATokenFromAnotherIssuerAndAudience_WhenValidating_ThenItIsStillAccepted()
    {
        var token = _handler.CreateToken(
            new JwtConfiguration(300, "someone-else", "somewhere-else", Secret,
                new Dictionary<string, string> { ["id"] = "1" }));

        Assert.True(await _handler.IsTokenValidAsync(token, Secret));
    }

    [Fact]
    public async Task GivenNoKeysAtAll_WhenValidating_ThenItIsRejected()
    {
        var token = _handler.CreateToken(Configuration(new Dictionary<string, string> { ["id"] = "1" }));

        Assert.False(await _handler.IsTokenValidAsync(token, Array.Empty<JwtKey>()));
    }

    [Fact]
    public void GivenAToken_WhenCreated_ThenItsLifetimeIsExpressedInUtc()
    {
        var token = _handler.CreateToken(Configuration(new Dictionary<string, string> { ["id"] = "1" }, 60));

        var read = new JwtSecurityTokenHandler().ReadJwtToken(token);

        Assert.InRange(read.ValidTo, DateTime.UtcNow.AddSeconds(50), DateTime.UtcNow.AddSeconds(70));
        Assert.InRange(read.ValidFrom, DateTime.UtcNow.AddSeconds(-10), DateTime.UtcNow.AddSeconds(10));
    }

    private static string CreateTokenExpiringAt(DateTime expiresUtc)
    {
        var handler = new JwtSecurityTokenHandler();
        var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Secret));

        var token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "issuer",
            Audience = "audience",
            Subject = new ClaimsIdentity([new Claim("id", "1")]),
            NotBefore = expiresUtc.AddMinutes(-10),
            Expires = expiresUtc,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature)
        });

        return handler.WriteToken(token);
    }
}
