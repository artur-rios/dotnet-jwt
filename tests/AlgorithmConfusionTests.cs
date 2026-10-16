using System.Buffers.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace ArturRios.Jwt.Tests;

/// <summary>
/// Refusal of algorithm confusion. A token's alg header is chosen by whoever wrote the token, so it
/// must never decide what kind of key checks it: an EC key validates ES256 alone and a secret HS256
/// alone.
/// </summary>
[Trait("Category", "Unit")]
public class AlgorithmConfusionTests
{
    private static readonly string s_pem = TestKeys.NewP256Pem();
    private static readonly JwtKey s_ecKey = JwtKey.FromEcPrivateKeyPem(s_pem);

    private readonly JwtHandler _handler = new();

    /// <summary>The EC key's public half as a SubjectPublicKeyInfo PEM: public material an attacker has.</summary>
    private static string PublicPem()
    {
        using var key = ECDsa.Create();
        key.ImportFromPem(s_pem);

        return key.ExportSubjectPublicKeyInfoPem();
    }

    /// <summary>An HS256 token keyed with arbitrary bytes, naming <paramref name="keyId"/>.</summary>
    private static string Hs256(byte[] keyBytes, string? keyId)
    {
        var handler = new JwtSecurityTokenHandler();

        return handler.WriteToken(handler.CreateToken(new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity([new Claim("id", "42")]),
            Expires = DateTime.UtcNow.AddMinutes(10),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(keyBytes) { KeyId = keyId }, SecurityAlgorithms.HmacSha256)
        }));
    }

    /// <summary>An unsigned token (<c>alg: none</c>) naming <paramref name="keyId"/>.</summary>
    private static string Unsigned(string keyId)
    {
        static string Segment(string json) => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(json));

        var expires = DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds();

        return Segment($"{{\"alg\":\"none\",\"typ\":\"JWT\",\"kid\":\"{keyId}\"}}") + "." +
               Segment($"{{\"id\":\"42\",\"exp\":{expires}}}") + ".";
    }

    [Fact]
    public async Task GivenTheHs256TokenTheHelperBuilds_WhenValidatedAgainstItsMatchingKey_ThenItIsValid()
    {
        // Positive control: without it, the refusals below could pass for the wrong reason.
        var token = Hs256(Encoding.ASCII.GetBytes(TestKeys.Secret), "k1");

        Assert.True(await _handler.IsTokenValidAsync(token, [new JwtKey("k1", TestKeys.Secret)]));
        Assert.True(await _handler.IsTokenValidAsync(token, TestKeys.Secret));
    }

    [Fact]
    public void GivenTheUnsignedTokenTheHelperBuilds_WhenRead_ThenItIsAReadableTokenNamingAlgNone()
    {
        // Positive control: without it, the unsigned-token refusal could pass because the token is unreadable.
        var handler = new JwtSecurityTokenHandler();
        var token = Unsigned(s_ecKey.Id);

        Assert.True(handler.CanReadToken(token));

        var read = handler.ReadJwtToken(token);

        Assert.Equal("none", read.Header.Alg);
        Assert.Equal(s_ecKey.Id, read.Header.Kid);
        Assert.Equal("42", read.Payload["id"]);
    }

    [Fact]
    public async Task GivenAnHs256TokenKeyedWithThePublicKeyPem_WhenValidatedAgainstTheEcKey_ThenItIsRefused()
    {
        var forged = Hs256(Encoding.ASCII.GetBytes(PublicPem()), s_ecKey.Id);

        Assert.False(await _handler.IsTokenValidAsync(forged, [s_ecKey.ToPublicKey()]));
    }

    [Fact]
    public async Task GivenAnHs256TokenKeyedWithThePublicKeyPemAndNoKid_WhenValidatedAgainstTheEcKey_ThenItIsRefused()
    {
        // No kid, so the handler tries every key in turn rather than the one a kid names.
        var forged = Hs256(Encoding.ASCII.GetBytes(PublicPem()), keyId: null);

        Assert.False(await _handler.IsTokenValidAsync(forged, [s_ecKey.ToPublicKey()]));
    }

    [Fact]
    public async Task GivenAnHs256TokenKeyedWithThePublishedKeySet_WhenValidatedAgainstTheEcKey_ThenItIsRefused()
    {
        var forged = Hs256(Encoding.UTF8.GetBytes(JwksDocument.From([s_ecKey.ToPublicKey()])), s_ecKey.Id);

        Assert.False(await _handler.IsTokenValidAsync(forged, [s_ecKey.ToPublicKey()]));
    }

    [Fact]
    public async Task GivenAnHs256TokenKeyedWithTheRawPublicPoint_WhenValidatedAgainstTheEcKey_ThenItIsRefused()
    {
        var point = Base64Url.DecodeFromChars(s_ecKey.PublicX!).Concat(Base64Url.DecodeFromChars(s_ecKey.PublicY!)).ToArray();

        Assert.False(await _handler.IsTokenValidAsync(Hs256(point, s_ecKey.Id), [s_ecKey.ToPublicKey()]));
    }

    [Fact]
    public async Task GivenAnUnsignedToken_WhenValidatedAgainstEitherKind_ThenItIsRefused()
    {
        Assert.False(await _handler.IsTokenValidAsync(Unsigned(s_ecKey.Id), [s_ecKey.ToPublicKey()]));
        Assert.False(await _handler.IsTokenValidAsync(Unsigned("k1"), [new JwtKey("k1", TestKeys.Secret)]));
    }

    [Fact]
    public async Task GivenAnEs256Token_WhenValidatedAgainstASecretUnderItsKid_ThenItIsRefused()
    {
        var token = _handler.CreateToken(TestKeys.Es256Configuration(s_ecKey));

        Assert.False(await _handler.IsTokenValidAsync(token, [new JwtKey(s_ecKey.Id, TestKeys.Secret)]));
        Assert.False(await _handler.IsTokenValidAsync(token, TestKeys.Secret));
    }

    [Fact]
    public async Task GivenAnHs256TokenUnderAKidAnEcKeyAnswersTo_WhenValidated_ThenItIsRefused()
    {
        var token = Hs256(Encoding.ASCII.GetBytes(TestKeys.Secret), "k1");

        Assert.False(await _handler.IsTokenValidAsync(token, [s_ecKey.ToPublicKey() with { Id = "k1" }]));
    }

    [Fact]
    public async Task GivenAKeySetMixingBothKinds_WhenValidating_ThenItIsRefusedAsAMistake()
    {
        var token = Hs256(Encoding.ASCII.GetBytes(TestKeys.Secret), null);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            _handler.IsTokenValidAsync(token, [new JwtKey("k1", TestKeys.Secret), s_ecKey.ToPublicKey()]));
    }

    [Fact]
    public void GivenAnHs256ConfigurationNamingAnEcSigningKey_WhenCreatingAToken_ThenItThrows()
    {
        var configuration = new JwtConfiguration(3600, "issuer", "audience", string.Empty,
            new Dictionary<string, string> { ["id"] = "42" })
        {
            Keys = [s_ecKey],
            SigningKeyId = s_ecKey.Id
        };

        var failure = Assert.Throws<InvalidOperationException>(() => _handler.CreateToken(configuration));

        Assert.Contains(JwtAlgorithms.ES256, failure.Message);
    }
}
