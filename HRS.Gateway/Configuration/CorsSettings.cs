namespace HRS.Gateway.Configuration;

public class CorsSettings
{
  public const string SectionName = "Cors";

  public string PolicyName { get; set; } = "HRSCorsPolicy";
  public string[] AllowedOrigins { get; set; } = Array.Empty<string>();
  public string[] AllowedMethods { get; set; } = Array.Empty<string>();
  public string[] AllowedHeaders { get; set; } = Array.Empty<string>();
  public bool AllowCredentials { get; set; } = true;
  public int MaxAge { get; set; } = 3600;
}