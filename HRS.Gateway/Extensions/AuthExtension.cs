using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace HRS.Gateway.Extensions;

public static class AuthExtensions
{
    public static IServiceCollection AddJwtAuthentication(this IServiceCollection services, IConfiguration config)
    {
        var auth0Domain = config["Auth0:Domain"];
        var auth0Audience = config["Auth0:Audience"];

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.Authority = $"https://{auth0Domain}/";
                options.Audience = auth0Audience;
                options.MapInboundClaims = false;
                options.TokenValidationParameters = new()
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = $"https://{auth0Domain}/",
                    ValidAudience = auth0Audience,
                    NameClaimType = "sub"
                };

                // Add event logging for debugging JWT validation
                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        var logger = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("JwtBearer");
                        logger.LogError("JWT Authentication failed: {Exception}", context.Exception?.Message);
                        logger.LogError("Token: {Token}", context.Request.Headers.Authorization.ToString());
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = context =>
                    {
                        var logger = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("JwtBearer");
                        var userId = context.Principal?.FindFirst("sub")?.Value;
                        logger.LogInformation("Token validated for user: {UserId}", userId);
                        return Task.CompletedTask;
                    }
                };
            });

        return services;
    }
}