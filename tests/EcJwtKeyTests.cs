using System.Buffers.Text;
using System.Security.Cryptography;

namespace ArturRios.Jwt.Tests;

/// <summary>
/// ES256 keys: read from a PEM or from a JWK's coordinates, named by their RFC 7638 thumbprint, refused
/// when they are not P-256 keys, and never printing their private half.
/// </summary>
[Trait("Category", "Unit")]
public class EcJwtKeyTests
{
    [Fact]
    public void GivenTheRfc7515PrivateKey_WhenReadFromPem_ThenItIsAnEs256SigningKeyNamedByItsThumbprint()
    {
        var key = JwtKey.FromEcPrivateKeyPem(TestKeys.Rfc7515Pem());

        Assert.Equal(TestKeys.Rfc7515Thumbprint, key.Id);
        Assert.Equal(TestKeys.Rfc7515Thumbprint, key.Thumbprint);
        Assert.Equal(JwtAlgorithms.ES256, key.Algorithm);
        Assert.True(key.IsAsymmetric);
        Assert.True(key.CanSign);
        Assert.Equal(string.Empty, key.Secret);
    }

    [Fact]
    public void GivenTheSec1FormOfAKey_WhenReadFromPem_ThenItIsTheSameKeyAsItsPkcs8Form()
    {
        using var generated = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var pkcs8 = JwtKey.FromEcPrivateKeyPem(generated.ExportPkcs8PrivateKeyPem());
        var sec1Pem = generated.ExportECPrivateKeyPem();
        var sec1 = JwtKey.FromEcPrivateKeyPem(sec1Pem);

        Assert.StartsWith("-----BEGIN EC PRIVATE KEY-----", sec1Pem);
        Assert.Equal(pkcs8.Id, sec1.Id);
        Assert.Equal(pkcs8.PublicX, sec1.PublicX);
        Assert.Equal(pkcs8.PublicY, sec1.PublicY);
        Assert.True(sec1.CanSign);
    }

    [Fact]
    public void GivenTheRfc7515PublicCoordinates_WhenRead_ThenTheKeyHasTheSameIdButCannotSign()
    {
        var key = JwtKey.FromEcPublicJwk(TestKeys.Rfc7515X, TestKeys.Rfc7515Y);

        Assert.Equal(TestKeys.Rfc7515Thumbprint, key.Id);
        Assert.True(key.IsAsymmetric);
        Assert.False(key.CanSign);
    }

    [Fact]
    public void GivenAPrivateKey_WhenItsPublicHalfIsTaken_ThenOnlyThePrivatePartIsDropped()
    {
        var key = TestKeys.NewEs256Key();

        var publicKey = key.ToPublicKey();

        Assert.Equal(key.Id, publicKey.Id);
        Assert.Equal(key.Thumbprint, publicKey.Thumbprint);
        Assert.True(key.CanSign);
        Assert.False(publicKey.CanSign);
    }

    [Fact]
    public void GivenTheSamePemTwice_WhenRead_ThenTheKeysAreEqual()
    {
        var pem = TestKeys.NewP256Pem();

        var first = JwtKey.FromEcPrivateKeyPem(pem);
        var second = JwtKey.FromEcPrivateKeyPem(pem);

        Assert.Equal(first, second);
        Assert.Equal(first.GetHashCode(), second.GetHashCode());
    }

    [Fact]
    public void GivenAPrivateKeyAndItsPublicHalf_WhenCompared_ThenTheyAreNotEqual()
    {
        var key = TestKeys.NewEs256Key();

        Assert.NotEqual(key, key.ToPublicKey());
    }

    [Fact]
    public void GivenTwoSecretKeysWithTheSameIdAndSecret_WhenCompared_ThenTheyAreEqualAsBefore()
    {
        Assert.Equal(new JwtKey("k1", TestKeys.Secret), new JwtKey("k1", TestKeys.Secret));
    }

    [Fact]
    public void GivenAnEcKey_WhenPrinted_ThenNoPrivateMaterialAppears()
    {
        var key = JwtKey.FromEcPrivateKeyPem(TestKeys.Rfc7515Pem());

        var printed = key.ToString();

        Assert.Contains(TestKeys.Rfc7515Thumbprint, printed);
        Assert.DoesNotContain(TestKeys.Rfc7515D, printed);
    }

    [Theory]
    [InlineData("P-384")]
    [InlineData("RSA")]
    [InlineData("public key")]
    [InlineData("encrypted")]
    [InlineData("two keys")]
    [InlineData("explicit P-256")]
    [InlineData("garbage")]
    public void GivenAPemThatIsNotAP256PrivateKey_WhenRead_ThenItIsRefusedWithoutEchoingIt(string kind)
    {
        var pem = UnusablePem(kind);

        var refusal = Assert.Throws<ArgumentException>(() => JwtKey.FromEcPrivateKeyPem(pem));

        Assert.Contains("P-256", refusal.Message);

        foreach (var line in pem.Split('\n').Select(line => line.Trim()).Where(line => line.Length > 0 && !line.StartsWith("-----")))
        {
            Assert.DoesNotContain(line, refusal.Message);
        }
    }

    [Fact]
    public void GivenCoordinatesOffTheCurve_WhenRead_ThenTheyAreRefused()
    {
        Assert.Throws<ArgumentException>(() => JwtKey.FromEcPublicJwk(TestKeys.Rfc7515X, TestKeys.OffCurveY));
    }

    [Fact]
    public void GivenACoordinateOf31Bytes_WhenRead_ThenItIsRefused()
    {
        var shortX = Base64Url.EncodeToString(Base64Url.DecodeFromChars(TestKeys.Rfc7515X)[..31]);

        Assert.Throws<ArgumentException>(() => JwtKey.FromEcPublicJwk(shortX, TestKeys.Rfc7515Y));
    }

    [Fact]
    public void GivenACoordinateThatIsNotBase64Url_WhenRead_ThenItIsRefused()
    {
        Assert.Throws<ArgumentException>(() => JwtKey.FromEcPublicJwk("@@@@", TestKeys.Rfc7515Y));
    }

    [Fact]
    public void GivenASecretKey_WhenInspected_ThenItIsAnHs256KeyWithNoThumbprint()
    {
        var key = new JwtKey("k1", TestKeys.Secret);

        Assert.Equal(JwtAlgorithms.HS256, key.Algorithm);
        Assert.False(key.IsAsymmetric);
        Assert.True(key.CanSign);
        Assert.Null(key.Thumbprint);
    }

    [Fact]
    public void GivenASecretKey_WhenItsPublicHalfIsAskedFor_ThenItIsRefused()
    {
        Assert.Throws<InvalidOperationException>(() => new JwtKey("k1", TestKeys.Secret).ToPublicKey());
    }

    [Fact]
    public void GivenABlankSecretKey_WhenTurnedIntoASecurityKey_ThenItIsRefused()
    {
        Assert.Throws<InvalidOperationException>(() => new JwtKey("k1", " ").ToSecurityKey());
    }

    private static string UnusablePem(string kind)
    {
        switch (kind)
        {
            case "P-384":
            {
                using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);

                return key.ExportPkcs8PrivateKeyPem();
            }
            case "RSA":
            {
                using var key = RSA.Create(2048);

                return key.ExportPkcs8PrivateKeyPem();
            }
            case "public key":
            {
                using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

                return key.ExportSubjectPublicKeyInfoPem();
            }
            case "encrypted":
            {
                using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

                return key.ExportEncryptedPkcs8PrivateKeyPem("passphrase",
                    new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1));
            }
            case "two keys":
                return TestKeys.NewP256Pem() + TestKeys.NewP256Pem();
            case "explicit P-256":
            {
                // P-256 itself, but spelled out as explicit curve parameters rather than named by its OID.
                using var named = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                using var key = ECDsa.Create(named.ExportExplicitParameters(includePrivateParameters: true));

                return key.ExportPkcs8PrivateKeyPem();
            }
            default:
                return "-----BEGIN PRIVATE KEY-----\nbm90LWEta2V5\n-----END PRIVATE KEY-----\n";
        }
    }
}
