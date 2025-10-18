using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace HRS.Gateway.Extensions;

public static class AuthExtensions
{
    public static IServiceCollection AddJwtAuthentication(this IServiceCollection services, IConfiguration config)
    {
        var jwtKey = config["Jwt:Key"];
        var jwtIssuer = config["Jwt:Issuer"];

        services.AddAuthentication("Bearer")
            .AddJwtBearer("Bearer", options =>
            {
                options.TokenValidationParameters = new()
                {
                    ValidateIssuer = true,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtIssuer,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey!))
                };
            });

        return services;
    }
}