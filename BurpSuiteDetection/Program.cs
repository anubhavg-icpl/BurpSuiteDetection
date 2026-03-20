using BurpSuiteDetection.Middleware;
using BurpSuiteDetection.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.AddBurpDetection(builder.Configuration);

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

// Burp detection runs FIRST — before anything else in the pipeline
app.UseBurpDetection();
app.UseHttpsRedirection();

// ── API Endpoints ──

app.MapGet("/api/weatherforecast", () =>
{
    var summaries = new[]
    {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild",
        "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };

    return Results.Ok(new
    {
        message = "Clean request — no proxy detected",
        data = Enumerable.Range(1, 5).Select(index => new
        {
            date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            temperatureC = Random.Shared.Next(-20, 55),
            summary = summaries[Random.Shared.Next(summaries.Length)]
        }).ToArray()
    });
})
.WithName("GetWeatherForecast");

// Shows detection result for the current request (always passes through)
app.MapGet("/api/security/check", (HttpContext context) =>
{
    if (context.Items["BurpDetectionResult"] is BurpDetectionResult result)
    {
        return Results.Ok(new
        {
            result.IsDetected,
            result.Message,
            result.ThreatScore,
            result.RiskLevel,
            result.Indicators,
            result.ClientIp,
            result.RequestMethod,
            result.RequestPath,
            result.Timestamp,
        });
    }

    return Results.Ok(new { message = "No detection data." });
})
.WithName("SecurityCheck");

app.MapGet("/health", () => Results.Ok(new { status = "healthy" }))
    .WithName("HealthCheck");

app.Run();

// Required for WebApplicationFactory<Program> in integration tests
public partial class Program { }
