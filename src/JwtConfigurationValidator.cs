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
        RuleFor(config => config.Secret).NotEmpty();
        RuleFor(config => config.Claims).NotEmpty();
    }
}
