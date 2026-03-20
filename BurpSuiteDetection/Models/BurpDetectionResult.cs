namespace BurpSuiteDetection.Models;

public sealed class BurpDetectionResult
{
    public bool IsDetected { get; init; }
    public int ThreatScore { get; init; }
    public string RiskLevel => ThreatScore switch
    {
        >= 80 => "CRITICAL",
        >= 60 => "HIGH",
        >= 40 => "MEDIUM",
        >= 20 => "LOW",
        _ => "NONE"
    };
    public string Message => IsDetected
        ? "BURP SUITE DETECTED"
        : "No proxy tool detected";
    public List<string> Indicators { get; init; } = [];
    public string ClientIp { get; init; } = string.Empty;
    public string RequestPath { get; init; } = string.Empty;
    public string RequestMethod { get; init; } = string.Empty;
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
}
