using System.Threading.RateLimiting;

namespace HRS.Gateway.Extensions;

public static class RateLimitExtensions
{
    public static IServiceCollection AddRateLimiting(this IServiceCollection services)
    {
        services.AddRateLimiter(options =>
        {
            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(_ =>
                RateLimitPartition.GetFixedWindowLimiter("global", _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 100,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 10,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst
                }));
        });
        return services;
    }
}