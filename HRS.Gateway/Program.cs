using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using HRS.Gateway.Extensions;
using Microsoft.AspNetCore.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddJsonFile("yarp.json", optional: false, reloadOnChange: true);

var jwtKey = builder.Configuration["Jwt:Key"] ?? throw new Exception("JWT key missing");
var jwtIssuer = builder.Configuration["Jwt:Issuer"];

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
        };
    });
builder.Services.AddJwtAuthentication(builder.Configuration);
builder.Services.AddAuthorization();
builder.Services.AddLogging();
builder.Services.AddRateLimiter(_ => _.AddFixedWindowLimiter("default", options =>
{
    options.PermitLimit = 100;
    options.Window = TimeSpan.FromMinutes(1);
    options.QueueLimit = 5;
}));

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.MapGet("/health", () => Results.Ok(new { status = "Gateway OK", time = DateTime.UtcNow }));
app.MapReverseProxy();

app.Run();