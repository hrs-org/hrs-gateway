using HRS.Gateway.Configuration;
using HRS.Gateway.Extensions;
using HRS.Gateway.Middleware;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration
    .AddJsonFile("yarp.json", optional: false, reloadOnChange: true)
    .AddJsonFile($"yarp.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true);

var corsSettings = builder.Configuration
    .GetSection(CorsSettings.SectionName)
    .Get<CorsSettings>() ?? new CorsSettings();

if (corsSettings.AllowedOrigins.Length == 0)
{
    throw new InvalidOperationException("CORS AllowedOrigins must be configured in appsettings.json");
}

builder.Logging.AddJsonConsole();
var logger = builder.Services.BuildServiceProvider().GetRequiredService<ILogger<Program>>();
logger.LogInformation("CORS Policy: {PolicyName}", corsSettings.PolicyName);
logger.LogInformation("Allowed Origins: {Origins}", string.Join(", ", corsSettings.AllowedOrigins));

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddJwtAuthentication(builder.Configuration);

builder.Services.AddCors(options =>
{
    options.AddPolicy(corsSettings.PolicyName, policy =>
    {
        if (corsSettings.AllowedOrigins.Contains("*"))
        {
            policy.AllowAnyOrigin();
        }
        else
        {
            policy.WithOrigins(corsSettings.AllowedOrigins)
                  .SetIsOriginAllowedToAllowWildcardSubdomains();
        }

        if (corsSettings.AllowedMethods.Contains("*"))
        {
            policy.AllowAnyMethod();
        }
        else
        {
            policy.WithMethods(corsSettings.AllowedMethods);
        }

        if (corsSettings.AllowedHeaders.Contains("*"))
        {
            policy.AllowAnyHeader();
        }
        else
        {
            policy.WithHeaders(corsSettings.AllowedHeaders);
        }

        if (corsSettings.AllowCredentials)
        {
            policy.AllowCredentials();
        }

        policy.SetPreflightMaxAge(TimeSpan.FromSeconds(corsSettings.MaxAge));

        policy.WithExposedHeaders("Content-Disposition", "X-Total-Count");
    });
});

builder.Services.AddHealthChecks();
builder.Services.AddSingleton<YarpRouteResolver>();

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("RequireAuth", policy => policy.RequireAuthenticatedUser());

builder.Services
    .AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();

    app.Logger.LogInformation("CORS enabled for development with origins: {Origins}",
        string.Join(", ", corsSettings.AllowedOrigins));
}

app.UseHttpsRedirection();
app.UseRouting();
app.UseCors(corsSettings.PolicyName);

app.Use(async (context, next) =>
{
    await next();

    // Apply secure defaults for API/gateway responses to reduce cache-related leakage risk.
    context.Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0";
    context.Response.Headers["Pragma"] = "no-cache";
    context.Response.Headers["Expires"] = "0";
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
});

app.UseAuthentication();
app.UseAuthorization();
app.UseMiddleware<AuthorizationMiddleware>();
app.UseMiddleware<SecurityLoggingMiddleware>();

app.MapControllers();

app.MapHealthChecks("/health");
app.MapGet("/health/ready", () => Results.Ok(new
{
    status = "ready",
    timestamp = DateTime.UtcNow,
    environment = app.Environment.EnvironmentName,
    corsPolicy = corsSettings.PolicyName,
    allowedOrigins = corsSettings.AllowedOrigins
})).AllowAnonymous();

app.MapGet("/health/live", () => Results.Ok(new
{
    status = "live",
    timestamp = DateTime.UtcNow
})).AllowAnonymous();

app.MapReverseProxy()
   .RequireAuthorization("RequireAuth");

app.Logger.LogInformation("HRS Gateway started");
app.Logger.LogInformation("Environment: {Environment}", app.Environment.EnvironmentName);
app.Logger.LogInformation("CORS Policy: {PolicyName}", corsSettings.PolicyName);

app.Run();