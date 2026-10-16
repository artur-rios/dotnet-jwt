using System.Text;
using FluentValidation;

namespace ArturRios.Jwt;

/// <summary>
/// Validates <see cref="JwtConfiguration"/> instances, ensuring they carry the values required to create a valid token.
/// </summary>
/// <remarks>
/// A configuration is held to its <see cref="JwtConfiguration.Algorithm"/>. An HS256 one keeps every rule it has
/// always had. An ES256 one holds EC keys only, each named by its RFC 7638 thumbprint, signs with one that has its
/// private half, and has no <see cref="JwtConfiguration.Secret"/>. The two kinds of key never share a configuration,
/// because a key set validates one algorithm.
/// </remarks>
public class JwtConfigurationValidator : AbstractValidator<JwtConfiguration>
{
    /// <summary>
    /// The shortest secret accepted, in bytes: HMAC-SHA256 needs a key at least as long as its 256-bit
    /// output (RFC 7518, section 3.2). Secrets are read as ASCII, one byte per character.
    /// </summary>
    private const int MinimumSecretBytes = 32;

    /// <summary>
    /// Initializes a new instance of the <see cref="JwtConfigurationValidator"/> class and configures its validation rules.
    /// </summary>
    public JwtConfigurationValidator()
    {
        RuleFor(config => config.Audience).NotEmpty();
        RuleFor(config => config.Issuer).NotEmpty();
        RuleFor(config => config.ExpirationInSeconds).NotEmpty().GreaterThan(0);
        RuleFor(config => config.Claims).NotEmpty();

        RuleFor(config => config.Algorithm)
            .Must(algorithm => algorithm is JwtAlgorithms.HS256 or JwtAlgorithms.ES256)
            .WithMessage(
                $"'{nameof(JwtConfiguration.Algorithm)}' must be '{JwtAlgorithms.HS256}' or '{JwtAlgorithms.ES256}'.");

        // A duplicate id makes the kid header ambiguous: two keys answer to it, and which one
        // validates a token would come down to ordering. The signature would still have to match, so
        // it is not a way in — but "it worked until we reordered the configuration" is not a failure
        // anyone should have to debug.
        RuleFor(config => config.Keys)
            .Must(keys => keys.Select(key => key.Id).Distinct().Count() == keys.Count)
            .When(config => config.Keys.Count > 0)
            .WithMessage($"'{nameof(JwtConfiguration.Keys)}' must not contain two keys with the same id.");

        RuleFor(config => config.Keys)
            .Must(keys => keys.All(key => !string.IsNullOrWhiteSpace(key.Id)))
            .When(config => config.Keys.Count > 0)
            .WithMessage($"Every key in '{nameof(JwtConfiguration.Keys)}' must have an id.");

        // The signing key must already be accepted. This is the rule that makes a rotation safe to
        // perform in the documented order: the new key is added to Keys everywhere first, and only
        // then does anything start signing with it. A configuration that signs with a key nothing
        // accepts would issue tokens that fail on their first use.
        RuleFor(config => config.SigningKeyId)
            .Must((config, signingKeyId) => config.Keys.Any(key => key.Id == signingKeyId))
            .When(config => !string.IsNullOrWhiteSpace(config.SigningKeyId))
            .WithMessage($"'{nameof(JwtConfiguration.SigningKeyId)}' must name a key in '{nameof(JwtConfiguration.Keys)}'.");

        When(config => config.Algorithm == JwtAlgorithms.HS256, HmacRules);
        When(config => config.Algorithm == JwtAlgorithms.ES256, EcdsaRules);
    }

    /// <summary>The rules every configuration had before ES256 existed, plus: no EC key among its keys.</summary>
    private void HmacRules()
    {
        // Secret signs whenever SigningKeyId names no key — JwtHandler.CreateToken falls back to it —
        // so it is required exactly then, and a configuration that signs with a key from Keys has no
        // use for it. Requiring it only when Keys was empty let a configuration with keys but no
        // SigningKeyId through with nothing to sign with, and CreateToken threw on it.
        When(config => string.IsNullOrWhiteSpace(config.SigningKeyId), () =>
        {
            RuleFor(config => config.Secret)
                .Cascade(CascadeMode.Stop)
                .NotEmpty()
                .WithMessage($"'{nameof(JwtConfiguration.Secret)}' must not be empty when no '{nameof(JwtConfiguration.SigningKeyId)}' is configured.")
                .Must(IsLongEnough)
                .WithMessage(
                    $"'{nameof(JwtConfiguration.Secret)}' must be at least {MinimumSecretBytes} bytes long, which HMAC-SHA256 requires.")
                // The same reason SigningKeyId must name a key in Keys: once Keys is set it is the set
                // of accepted keys, and a token signed with anything else fails on its first use.
                .Must((config, secret) => config.Keys.Count == 0 || config.Keys.Any(key => key.Secret == secret))
                .WithMessage(
                    $"'{nameof(JwtConfiguration.Secret)}' signs the tokens when no '{nameof(JwtConfiguration.SigningKeyId)}' is configured, so it must be the secret of a key in '{nameof(JwtConfiguration.Keys)}'.");
        });

        RuleFor(config => config.Keys)
            .Must(keys => keys.All(key => !key.IsAsymmetric))
            .When(config => config.Keys.Count > 0)
            .WithMessage(
                $"An {JwtAlgorithms.HS256} configuration accepts only {JwtAlgorithms.HS256} keys, but '{nameof(JwtConfiguration.Keys)}' holds an {JwtAlgorithms.ES256} key. Set '{nameof(JwtConfiguration.Algorithm)}' to {JwtAlgorithms.ES256}, or keep the two kinds of key in separate configurations.");

        RuleFor(config => config.Keys)
            .Must(keys => keys.All(key => !string.IsNullOrWhiteSpace(key.Secret)))
            .When(config => config.Keys.Count > 0)
            .WithMessage($"Every key in '{nameof(JwtConfiguration.Keys)}' must have a secret.");

        RuleFor(config => config.Keys)
            .Must(keys => keys.Where(key => !string.IsNullOrWhiteSpace(key.Secret)).All(key => IsLongEnough(key.Secret)))
            .When(config => config.Keys.Count > 0)
            .WithMessage(
                $"Every key in '{nameof(JwtConfiguration.Keys)}' must have a secret of at least {MinimumSecretBytes} bytes, which HMAC-SHA256 requires.");
    }

    /// <summary>The rules of an ES256 configuration.</summary>
    private void EcdsaRules()
    {
        RuleFor(config => config.Secret)
            .Empty()
            .WithMessage(
                $"'{nameof(JwtConfiguration.Secret)}' must be empty in an {JwtAlgorithms.ES256} configuration, which signs with a private key from '{nameof(JwtConfiguration.Keys)}'.");

        RuleFor(config => config.SigningKeyId)
            .NotEmpty()
            .WithMessage(
                $"An {JwtAlgorithms.ES256} configuration signs with the key '{nameof(JwtConfiguration.SigningKeyId)}' names, so it is required.");

        RuleFor(config => config.Keys)
            .Must(keys => keys.All(key => key.IsAsymmetric))
            .WithMessage(
                $"An {JwtAlgorithms.ES256} configuration accepts only {JwtAlgorithms.ES256} keys: every key in '{nameof(JwtConfiguration.Keys)}' must be an EC P-256 key.");

        // The kid is derived, never configured: it is what a published key set names a key by, so a key
        // renamed with a with-expression would sign tokens no consumer can match to a key.
        RuleFor(config => config.Keys)
            .Must(keys => keys.Where(key => key.IsAsymmetric).All(key => key.Id == key.Thumbprint))
            .WithMessage(
                $"Every {JwtAlgorithms.ES256} key in '{nameof(JwtConfiguration.Keys)}' must have its RFC 7638 thumbprint as its id.");

        RuleFor(config => config.SigningKeyId)
            .Must((config, signingKeyId) => config.Keys.FirstOrDefault(key => key.Id == signingKeyId) is not { } key || key.CanSign)
            .When(config => !string.IsNullOrWhiteSpace(config.SigningKeyId))
            .WithMessage(
                $"The key '{nameof(JwtConfiguration.SigningKeyId)}' names must hold its private half: a public key validates tokens but cannot sign them.");
    }

    private static bool IsLongEnough(string secret) => Encoding.ASCII.GetByteCount(secret) >= MinimumSecretBytes;
}
