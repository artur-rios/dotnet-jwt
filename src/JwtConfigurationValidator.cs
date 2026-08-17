using FluentValidation;

namespace ArturRios.Jwt;

/// <summary>
/// Validates <see cref="JwtConfiguration"/> instances, ensuring they carry the values required to create a valid token.
/// </summary>
public class JwtConfigurationValidator : AbstractValidator<JwtConfiguration>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="JwtConfigurationValidator"/> class and configures its validation rules.
    /// </summary>
    public JwtConfigurationValidator()
    {
        RuleFor(config => config.Audience).NotEmpty();
        RuleFor(config => config.Issuer).NotEmpty();
        RuleFor(config => config.ExpirationInSeconds).NotEmpty().GreaterThan(0);
        RuleFor(config => config.Claims).NotEmpty();

        // Secret was unconditionally required before Keys existed, and a configuration that supplies
        // its key material through Keys has no use for it. Requiring one of the two keeps every
        // configuration that was valid before valid now, without forcing a redundant secret on one
        // that has moved on from it.
        RuleFor(config => config.Secret)
            .NotEmpty()
            .When(config => config.Keys.Count == 0)
            .WithMessage($"'{nameof(JwtConfiguration.Secret)}' must not be empty when no keys are configured.");

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

        RuleFor(config => config.Keys)
            .Must(keys => keys.All(key => !string.IsNullOrWhiteSpace(key.Secret)))
            .When(config => config.Keys.Count > 0)
            .WithMessage($"Every key in '{nameof(JwtConfiguration.Keys)}' must have a secret.");

        // The signing key must already be accepted. This is the rule that makes a rotation safe to
        // perform in the documented order: the new key is added to Keys everywhere first, and only
        // then does anything start signing with it. A configuration that signs with a key nothing
        // accepts would issue tokens that fail on their first use.
        RuleFor(config => config.SigningKeyId)
            .Must((config, signingKeyId) => config.Keys.Any(key => key.Id == signingKeyId))
            .When(config => !string.IsNullOrWhiteSpace(config.SigningKeyId))
            .WithMessage($"'{nameof(JwtConfiguration.SigningKeyId)}' must name a key in '{nameof(JwtConfiguration.Keys)}'.");
    }
}
