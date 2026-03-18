using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace HRS.Gateway.Middleware;

public sealed class SecurityLoggingMiddleware
{
    private const string CorrelationIdHeader = "X-Correlation-Id";

    private readonly RequestDelegate _next;
    private readonly ILogger<SecurityLoggingMiddleware> _logger;
    private readonly YarpRouteResolver _routeResolver;

    public SecurityLoggingMiddleware(
        RequestDelegate next,
        ILogger<SecurityLoggingMiddleware> logger,
        YarpRouteResolver routeResolver)
    {
        _next = next;
        _logger = logger;
        _routeResolver = routeResolver;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var correlationId = GetOrCreateCorrelationId(context);
        context.Response.Headers[CorrelationIdHeader] = correlationId;

        var timer = Stopwatch.StartNew();
        await _next(context);
        timer.Stop();

        var route = _routeResolver.Resolve(context.Request.Path);
        var userId = HashIdentifier(context.User.FindFirst("sub")?.Value ?? "anonymous");
        var sourceIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var downstreamStatusCode = context.Response.StatusCode;

        _logger.LogInformation(
          "event_type={EventType} method={Method} path={Path} status={StatusCode} downstream_status_code={DownstreamStatusCode} duration_ms={DurationMs} correlation_id={CorrelationId} route_id={RouteId} cluster_id={ClusterId} downstream_path={DownstreamPath} user_id={UserId} source_ip={SourceIp}",
            "gateway.request",
            context.Request.Method,
            context.Request.Path.Value,
            context.Response.StatusCode,
          downstreamStatusCode,
            timer.ElapsedMilliseconds,
            correlationId,
            route.RouteId,
            route.ClusterId,
            context.Request.Path.Value,
            userId,
            sourceIp);

        if (context.Response.StatusCode is StatusCodes.Status401Unauthorized or StatusCodes.Status403Forbidden)
        {
            _logger.LogWarning(
                "event_type={EventType} status={StatusCode} downstream_status_code={DownstreamStatusCode} method={Method} path={Path} correlation_id={CorrelationId} route_id={RouteId} cluster_id={ClusterId} user_id={UserId} source_ip={SourceIp}",
                "gateway.authorization_denied",
                context.Response.StatusCode,
                downstreamStatusCode,
                context.Request.Method,
                context.Request.Path.Value,
                correlationId,
                route.RouteId,
                route.ClusterId,
                userId,
                sourceIp);
        }
    }

    private static string GetOrCreateCorrelationId(HttpContext context)
    {
        var incoming = context.Request.Headers[CorrelationIdHeader].FirstOrDefault();
        return string.IsNullOrWhiteSpace(incoming) ? Guid.NewGuid().ToString("N") : incoming;
    }

    private static string HashIdentifier(string value)
    {
        var inputBytes = Encoding.UTF8.GetBytes(value);
        var hashBytes = SHA256.HashData(inputBytes);
        return Convert.ToHexString(hashBytes)[..16];
    }
}

public sealed class YarpRouteResolver
{
    private readonly List<RouteInfo> _routes;

    public YarpRouteResolver(IConfiguration configuration)
    {
        _routes = configuration
            .GetSection("ReverseProxy:Routes")
            .GetChildren()
            .Select(routeSection =>
            {
                var matchPath = routeSection.GetSection("Match")["Path"] ?? string.Empty;
                var hasCatchAll = matchPath.Contains("{**catch-all}", StringComparison.OrdinalIgnoreCase);

                var normalizedPrefix = hasCatchAll
                    ? matchPath.Replace("/{**catch-all}", string.Empty, StringComparison.OrdinalIgnoreCase)
                    : matchPath;

                return new RouteInfo(
                    routeSection.Key,
                    routeSection["ClusterId"] ?? "unknown-cluster",
                    normalizedPrefix,
                    hasCatchAll);
            })
            .ToList();
    }

    public RouteInfo Resolve(PathString requestPath)
    {
        var path = requestPath.Value ?? string.Empty;

        foreach (var route in _routes)
        {
            if (route.HasCatchAll)
            {
                if (path.StartsWith(route.MatchPath, StringComparison.OrdinalIgnoreCase))
                {
                    return route;
                }
            }
            else if (string.Equals(path, route.MatchPath, StringComparison.OrdinalIgnoreCase))
            {
                return route;
            }
        }

        return new RouteInfo("unmatched", "unmatched", path, false);
    }
}

public sealed record RouteInfo(string RouteId, string ClusterId, string MatchPath, bool HasCatchAll);