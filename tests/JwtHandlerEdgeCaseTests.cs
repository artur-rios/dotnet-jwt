using System.Globalization;
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
    [InlineData("W10.e30.")] // a header that is a JSON array, which the reader throws an ArgumentException on
    [InlineData("e30.W10.")] // a payload that is a JSON array
    [InlineData("e30.e30.")] // readable, with no header member or claim at all
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
    [InlineData("W10.e30.")] // a header that is a JSON array, which the reader throws an ArgumentException on
    [InlineData("e30.W10.")] // a payload that is a JSON array
    [InlineData("e30.e30.")] // readable, with no header member or claim at all
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

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task GivenABlankSecret_WhenValidating_ThenItIsRejectedRatherThanThrown(string secret)
    {
        // A blank secret validates nothing. It used to reach SymmetricSecurityKey, which throws on a
        // zero-length key, so a missing secret surfaced as an exception on every request.
        var token = _handler.CreateToken(Configuration(new Dictionary<string, string> { ["id"] = "1" }));

        Assert.False(await _handler.IsTokenValidAsync(token, secret));
    }

    [Fact]
    public async Task GivenAKeySetHoldingABlankSecret_WhenValidatingATokenWithNoKeyId_ThenTheOtherKeysAreStillTried()
    {
        var token = _handler.CreateToken(Configuration(new Dictionary<string, string> { ["id"] = "1" }));

        Assert.True(await _handler.IsTokenValidAsync(token, [new JwtKey("blank", string.Empty), new JwtKey("k1", Secret)]));
    }

    [Fact]
    public async Task GivenATokenNamingAKeyWithABlankSecret_WhenValidating_ThenItIsRejectedRatherThanThrown()
    {
        var token = _handler.CreateToken(Configuration(new Dictionary<string, string> { ["id"] = "1" }) with
        {
            Keys = [new JwtKey("k1", Secret)],
            SigningKeyId = "k1"
        });

        Assert.False(await _handler.IsTokenValidAsync(token, [new JwtKey("k1", " ")]));
    }

    [Theory]
    [InlineData(SecurityAlgorithms.HmacSha384)]
    [InlineData(SecurityAlgorithms.HmacSha512)]
    public async Task GivenATokenSignedWithTheRightSecretButAnotherAlgorithm_WhenValidating_ThenItIsRejected(string algorithm)
    {
        // Tokens are created with HMAC-SHA256 and nothing else, so nothing else is accepted: the
        // algorithm a token names is attacker-controlled input, and is pinned rather than trusted.
        var secret = Secret + Secret;
        var token = CreateTokenSignedWith(secret, algorithm);

        Assert.False(await _handler.IsTokenValidAsync(token, secret));
        Assert.False(await _handler.IsTokenValidAsync(token, [new JwtKey("k1", secret)]));
    }

    [Fact]
    public async Task GivenATokenSignedWithHmacSha256ByAnotherLibrary_WhenValidating_ThenItIsAccepted()
    {
        Assert.True(await _handler.IsTokenValidAsync(CreateTokenSignedWith(Secret, SecurityAlgorithms.HmacSha256), Secret));
    }

    private static string CreateTokenSignedWith(string secret, string algorithm)
    {
        var handler = new JwtSecurityTokenHandler();
        var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret));

        return handler.WriteToken(handler.CreateToken(new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity([new Claim("id", "1")]),
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(key, algorithm)
        }));
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

    [Theory]
    [InlineData("")]
    [InlineData("not-a-token")]
    [InlineData("a.b.c")]
    [InlineData("W10.e30.")]
    [InlineData("e30.e30.")]
    public async Task GivenSomethingThatIsNotAToken_WhenValidating_ThenItIsRefusedRatherThanThrown(string token)
    {
        Assert.False(await _handler.IsTokenValidAsync(token, Secret));
        Assert.False(await _handler.IsTokenValidAsync(token, [new JwtKey("k1", Secret)]));
    }

    [Fact]
    public async Task GivenATokenWithABlankKeyId_WhenRead_ThenItHasNoKeyIdAndEveryKeyIsTried()
    {
        var token = TestTokens.Hs256(Secret, DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddMinutes(5), keyId: " ");

        Assert.Null(_handler.GetKeyIdFromToken(token));
        Assert.True(await _handler.IsTokenValidAsync(token, [new JwtKey("other", Secret + "!"), new JwtKey("k1", Secret)]));
    }

    [Theory]
    [InlineData("pt-BR", "-7", -7)]
    [InlineData("pt-BR", "+7", 7)]
    [InlineData("pt-BR", "007", 7)]
    [InlineData("pt-BR", " 7 ", 7)]
    [InlineData("pt-BR", "2147483647", int.MaxValue)]
    [InlineData("pt-BR", "-2147483648", int.MinValue)]
    [InlineData("", "-7", -7)]
    [InlineData("", "2147483647", int.MaxValue)]
    public void GivenAnIdClaimWithASignPaddingOrALimit_WhenReadingTheUserIdUnderACulture_ThenItIsParsed(
        string culture, string id, int expected)
    {
        var token = _handler.CreateToken(Configuration(new Dictionary<string, string> { ["id"] = id }));

        using (new CultureScope(culture))
        {
            Assert.Equal(expected, _handler.GetUserIdFromToken(token));
        }
    }

    [Theory]
    [InlineData("pt-BR", "1.000")] // pt-BR's group separator
    [InlineData("pt-BR", "1,5")] // pt-BR's decimal separator
    [InlineData("pt-BR", "7.0")]
    [InlineData("pt-BR", "2147483648")]
    [InlineData("pt-BR", "")]
    [InlineData("", "1,000")]
    [InlineData("", "1.5")]
    [InlineData("", "\u0667")] // an Arabic-Indic seven
    public void GivenAnIdClaimThatIsNotAPlainInteger_WhenReadingTheUserIdUnderACulture_ThenNullComesBack(
        string culture, string id)
    {
        var token = _handler.CreateToken(Configuration(new Dictionary<string, string> { ["id"] = id }));

        using (new CultureScope(culture))
        {
            Assert.Null(_handler.GetUserIdFromToken(token));
        }
    }

    [Fact]
    public void GivenAConfiguration_WhenATokenIsCreated_ThenItCarriesTheIssuerTheAudienceAndEveryClaim()
    {
        var token = _handler.CreateToken(Configuration(new Dictionary<string, string> { ["id"] = "1", ["role"] = "admin" }));

        var read = new JwtSecurityTokenHandler().ReadJwtToken(token);

        Assert.Equal("issuer", read.Issuer);
        Assert.Equal(["audience"], read.Audiences);
        Assert.Equal("1", read.Claims.Single(claim => claim.Type == "id").Value);
        Assert.Equal("admin", read.Claims.Single(claim => claim.Type == "role").Value);
        Assert.Equal(SecurityAlgorithms.HmacSha256, read.Header.Alg);
    }

    [Fact]
    public void GivenAnExpiration_WhenATokenIsCreated_ThenItLivesExactlyThatManySecondsFromItsStart()
    {
        var token = _handler.CreateToken(Configuration(new Dictionary<string, string> { ["id"] = "1" }, 3600));

        var read = new JwtSecurityTokenHandler().ReadJwtToken(token);

        Assert.Equal(TimeSpan.FromSeconds(3600), read.ValidTo - read.ValidFrom);
    }

    [Fact]
    public async Task GivenNoClaims_WhenATokenIsCreated_ThenItIsValidAndCarriesNoUserId()
    {
        // The validator requires claims; the handler does not.
        var token = _handler.CreateToken(Configuration(new Dictionary<string, string>()));

        Assert.True(await _handler.IsTokenValidAsync(token, Secret));
        Assert.Null(_handler.GetUserIdFromToken(token));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void GivenNoSecretAndNoSigningKey_WhenCreatingAToken_ThenItThrows(string secret)
    {
        var configuration = Configuration(new Dictionary<string, string> { ["id"] = "1" }) with { Secret = secret };

        Assert.ThrowsAny<ArgumentException>(() => _handler.CreateToken(configuration));
    }

    [Fact]
    public void GivenASecretShorterThan32Bytes_WhenCreatingAToken_ThenItThrows()
    {
        // The validator refuses such a configuration; the handler fails rather than sign with a weak key.
        var configuration = Configuration(new Dictionary<string, string> { ["id"] = "1" }) with
        {
            Secret = new string('s', 31)
        };

        Assert.ThrowsAny<ArgumentException>(() => _handler.CreateToken(configuration));
    }

    [Fact]
    public async Task GivenTwoNonAsciiSecretsOfTheSameLength_WhenValidating_ThenEachAcceptsTheOthersTokens()
    {
        // As JwtHandler documents: secrets are read as ASCII, so every character above U+007F becomes '?'.
        var token = _handler.CreateToken(Configuration(new Dictionary<string, string> { ["id"] = "1" }) with
        {
            Secret = new string('é', 32)
        });

        Assert.True(await _handler.IsTokenValidAsync(token, new string('ü', 32)));
        Assert.True(await _handler.IsTokenValidAsync(token, new string('?', 32)));
    }

    [Fact]
    public async Task GivenNoKeyCollection_WhenValidating_ThenItIsRefusedAsAnArgument()
    {
        var token = _handler.CreateToken(Configuration(new Dictionary<string, string> { ["id"] = "1" }));

        await Assert.ThrowsAsync<ArgumentNullException>(() => _handler.IsTokenValidAsync(token, (IEnumerable<JwtKey>)null!));
    }

    [Fact]
    public async Task GivenAKeySetWhereTheTokensKeyIdAppearsTwice_WhenValidating_ThenTheFirstKeyWithThatIdDecides()
    {
        var token = _handler.CreateToken(Configuration(new Dictionary<string, string> { ["id"] = "1" }) with
        {
            Keys = [new JwtKey("k1", Secret)],
            SigningKeyId = "k1"
        });
        var other = new JwtKey("k1", "another-secret-that-is-32-bytes-long!!!");

        Assert.True(await _handler.IsTokenValidAsync(token, [new JwtKey("k1", Secret), other]));
        Assert.False(await _handler.IsTokenValidAsync(token, [other, new JwtKey("k1", Secret)]));
    }

    /// <summary>Sets the current culture until disposed; an empty name is the invariant culture.</summary>
    private sealed class CultureScope : IDisposable
    {
        private readonly CultureInfo _previous = CultureInfo.CurrentCulture;

        public CultureScope(string name) => CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(name);

        public void Dispose() => CultureInfo.CurrentCulture = _previous;
    }
}
