using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace ArturRios.Jwt.Tests;

/// <summary>
/// ES256 end to end: the RFC 7515 known answer, tokens signed and verified with a key pair, and the kid
/// choosing which key checks a token.
/// </summary>
[Trait("Category", "Unit")]
public class Es256HandlerTests
{
    private readonly JwtHandler _handler = new();

    private static JwtConfiguration Es256(JwtKey signingKey, params JwtKey[] alsoAccepted) =>
        TestKeys.Es256Configuration(signingKey) with { Keys = [signingKey, .. alsoAccepted] };

    private static Task<TokenValidationResult> VerifyRfc7515(string jws) =>
        new JsonWebTokenHandler().ValidateTokenAsync(jws, new TokenValidationParameters
        {
            IssuerSigningKey = JwtKey.FromEcPublicJwk(TestKeys.Rfc7515X, TestKeys.Rfc7515Y).ToSecurityKey(),
            ValidAlgorithms = [JwtAlgorithms.ES256],
            ValidateIssuer = false,
            ValidateAudience = false,
            // The RFC's example expired in 2011; only the signature is the known answer.
            ValidateLifetime = false,
            RequireExpirationTime = false
        });

    [Fact]
    public async Task GivenTheRfc7515AppendixA3Jws_WhenVerifiedWithItsPublicJwk_ThenTheSignatureIsValid()
    {
        var result = await VerifyRfc7515(TestKeys.Rfc7515Jws);

        Assert.True(result.IsValid, result.Exception?.Message);
    }

    [Fact]
    public async Task GivenTheRfc7515AppendixA3JwsWithAnAlteredSignature_WhenVerified_ThenItIsRefused()
    {
        // 'D' → 'E' changes the first byte of R, so the signature no longer matches.
        var segments = TestKeys.Rfc7515Jws.Split('.');
        var altered = $"{segments[0]}.{segments[1]}.E{segments[2][1..]}";

        var result = await VerifyRfc7515(altered);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void GivenAnEs256Configuration_WhenATokenIsCreated_ThenItIsSignedEs256AndNamesItsKey()
    {
        var key = TestKeys.NewEs256Key();

        var token = _handler.CreateToken(Es256(key));

        var header = new JwtSecurityTokenHandler().ReadJwtToken(token).Header;
        Assert.Equal(JwtAlgorithms.ES256, header.Alg);
        Assert.Equal(key.Id, header.Kid);
    }

    [Fact]
    public async Task GivenTheRfc7515Key_WhenSigningAndVerifyingWithItsPublicJwk_ThenTheRoundTripHolds()
    {
        var token = _handler.CreateToken(Es256(JwtKey.FromEcPrivateKeyPem(TestKeys.Rfc7515Pem())));

        Assert.True(await _handler.IsTokenValidAsync(token, [JwtKey.FromEcPublicJwk(TestKeys.Rfc7515X, TestKeys.Rfc7515Y)]));
    }

    [Fact]
    public async Task GivenAnEs256Token_WhenValidatedWithThePublicHalfOfItsKey_ThenItIsValid()
    {
        var key = TestKeys.NewEs256Key();
        var token = _handler.CreateToken(Es256(key));

        Assert.True(await _handler.IsTokenValidAsync(token, [key.ToPublicKey()]));
    }

    [Fact]
    public async Task GivenAnEs256Token_WhenValidatedWithAnotherKey_ThenItIsRefused()
    {
        var token = _handler.CreateToken(Es256(TestKeys.NewEs256Key()));

        Assert.False(await _handler.IsTokenValidAsync(token, [TestKeys.NewEs256Key().ToPublicKey()]));
    }

    [Fact]
    public async Task GivenATokenSignedWithTheSecondOfTwoKeys_WhenValidatedAgainstBoth_ThenTheKidSelectsIt()
    {
        var first = TestKeys.NewEs256Key();
        var second = TestKeys.NewEs256Key();
        var token = _handler.CreateToken(Es256(second, first));

        Assert.True(await _handler.IsTokenValidAsync(token, [first.ToPublicKey(), second.ToPublicKey()]));
    }

    [Fact]
    public async Task GivenAKidNamingAKeyThatDidNotSignTheToken_WhenValidated_ThenItIsRefused()
    {
        // The kid selects a key and grants nothing: a token that names a key it was not signed with fails
        // that key's signature check and is not tried against the others.
        var named = TestKeys.NewEs256Key();
        var impostor = TestKeys.NewEs256Key() with { Id = named.Id };
        var token = _handler.CreateToken(Es256(impostor));

        Assert.Equal(named.Id, _handler.GetKeyIdFromToken(token));
        Assert.False(await _handler.IsTokenValidAsync(token, [named.ToPublicKey()]));
    }

    [Fact]
    public async Task GivenAnExpiredEs256Token_WhenValidated_ThenItIsRefused()
    {
        var key = TestKeys.NewEs256Key();
        var token = _handler.CreateToken(Es256(key) with { ExpirationInSeconds = 1 });

        await Task.Delay(TimeSpan.FromSeconds(2));

        Assert.False(await _handler.IsTokenValidAsync(token, [key.ToPublicKey()]));
    }

    [Fact]
    public void GivenAnEs256ConfigurationWithoutASigningKeyId_WhenCreatingAToken_ThenItThrows()
    {
        var configuration = Es256(TestKeys.NewEs256Key()) with { SigningKeyId = null };

        Assert.Throws<InvalidOperationException>(() => _handler.CreateToken(configuration));
    }

    [Fact]
    public void GivenAnEs256ConfigurationSigningWithAPublicKey_WhenCreatingAToken_ThenItThrows()
    {
        var configuration = Es256(TestKeys.NewEs256Key().ToPublicKey());

        var failure = Assert.Throws<InvalidOperationException>(() => _handler.CreateToken(configuration));

        Assert.Contains("private", failure.Message);
    }

    [Fact]
    public void GivenAnUnknownAlgorithm_WhenCreatingAToken_ThenItThrowsNamingIt()
    {
        var configuration = new JwtConfiguration(3600, "issuer", "audience", TestKeys.Secret,
            new Dictionary<string, string> { ["id"] = "42" })
        { Algorithm = "RS256" };

        var failure = Assert.Throws<InvalidOperationException>(() => _handler.CreateToken(configuration));

        Assert.Contains("RS256", failure.Message);
    }
}
