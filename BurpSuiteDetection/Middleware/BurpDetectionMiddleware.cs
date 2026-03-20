using System.Text.Json;
using BurpSuiteDetection.Models;
using BurpSuiteDetection.Services;
using Microsoft.Extensions.Options;

namespace BurpSuiteDetection.Middleware;

public sealed class BurpDetectionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly BurpDetectionOptions _options;
    private readonly ILogger<BurpDetectionMiddleware> _logger;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
    };

    public BurpDetectionMiddleware(
        RequestDelegate next,
        IOptions<BurpDetectionOptions> options,
        ILogger<BurpDetectionMiddleware> logger)
    {
        _next = next;
        _options = options.Value;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, BurpDetectionService detectionService)
    {
        // Skip excluded paths
        var path = context.Request.Path.Value ?? string.Empty;
        if (_options.ExcludedPaths.Any(p =>
                path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
        {
            await _next(context);
            return;
        }

        var result = detectionService.Analyze(context);

        // Store result so endpoints can read it
        context.Items["BurpDetectionResult"] = result;

        if (result.IsDetected)
        {
            // ── Big clear console banner ──
            _logger.LogCritical(
                """

                ============================================
                    BURP SUITE DETECTED
                ============================================
                  IP       : {ClientIp}
                  Method   : {Method}
                  Path     : {Path}
                  Score    : {Score}/100  ({Risk})
                  Indicators:
                {Indicators}
                ============================================
                """,
                result.ClientIp,
                result.RequestMethod,
                result.RequestPath,
                result.ThreatScore,
                result.RiskLevel,
                string.Join("\n", result.Indicators.Select(i => $"    - {i}")));

            if (_options.BlockRequests)
            {
                context.Response.StatusCode = _options.BlockStatusCode;
                context.Response.ContentType = "application/json";

                var body = new
                {
                    detected = true,
                    message = "BURP SUITE DETECTED",
                    threatScore = result.ThreatScore,
                    riskLevel = result.RiskLevel,
                    clientIp = result.ClientIp,
                    indicators = result.Indicators,
                    timestamp = result.Timestamp,
                };

                await context.Response.WriteAsJsonAsync(body, JsonOptions);
                return;
            }

            // If not blocking, add a response header so caller knows
            context.Response.Headers["X-Burp-Detected"] = "true";
            context.Response.Headers["X-Threat-Score"] = result.ThreatScore.ToString();
        }
        else if (result.ThreatScore > 0)
        {
            // Some signals but below threshold — log as warning
            _logger.LogWarning(
                "Suspicious request — IP: {ClientIp}, Path: {Path}, Score: {Score}, Indicators: [{Indicators}]",
                result.ClientIp,
                result.RequestPath,
                result.ThreatScore,
                string.Join("; ", result.Indicators));
        }

        await _next(context);
    }
}

public static class BurpDetectionMiddlewareExtensions
{
    public static IApplicationBuilder UseBurpDetection(this IApplicationBuilder app)
    {
        return app.UseMiddleware<BurpDetectionMiddleware>();
    }

    public static IServiceCollection AddBurpDetection(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.Configure<BurpDetectionOptions>(
            configuration.GetSection(BurpDetectionOptions.SectionName));

        services.AddScoped<BurpDetectionService>();

        return services;
    }
}
