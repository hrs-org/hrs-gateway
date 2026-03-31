namespace HRS.Gateway.Middleware;

/// <summary>
/// Middleware to enforce JWT authorization on protected routes while allowing public routes
/// </summary>
public class AuthorizationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<AuthorizationMiddleware> _logger;

    // Routes that don't require authentication
    private static readonly HashSet<string> PublicRoutes = new(StringComparer.OrdinalIgnoreCase)
    {
        "/health",
        "/health/users",
        "/health/email",
        "/health/maintenance",
        "/health/payment",
        "/health/inventory",
        "/health/order",
        "/api/users/register/customer",
        "/api/stores/register"
    };

    public AuthorizationMiddleware(RequestDelegate next, ILogger<AuthorizationMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? string.Empty;

        // Check if the route is public
        if (IsPublicRoute(path))
        {
            _logger.LogDebug("Public route accessed: {Path}", path);
            await _next(context);
            return;
        }

        // Check if user is authenticated
        if (!context.User.Identity?.IsAuthenticated ?? true)
        {
            _logger.LogWarning("Unauthorized access attempt to protected route: {Path}", path);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new
            {
                error = "Unauthorized",
                message = "Valid JWT token required"
            });
            return;
        }

        _logger.LogDebug("Authenticated user accessing route: {Path}", path);
        await _next(context);
    }

    private static bool IsPublicRoute(string path)
    {
        // Exact match
        if (PublicRoutes.Contains(path))
            return true;

        // Check for prefix matches (e.g., /auth/register)
        foreach (var publicRoute in PublicRoutes)
        {
            if (path.StartsWith(publicRoute + "/", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }
}
