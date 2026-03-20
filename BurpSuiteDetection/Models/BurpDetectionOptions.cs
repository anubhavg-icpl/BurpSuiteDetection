namespace BurpSuiteDetection.Models;

public sealed class BurpDetectionOptions
{
    public const string SectionName = "BurpDetection";

    /// <summary>Minimum threat score (0-100) to flag as detected.</summary>
    public int BlockingThreshold { get; set; } = 30;

    /// <summary>Whether to block detected requests or just log + tag them.</summary>
    public bool BlockRequests { get; set; } = true;

    /// <summary>HTTP status code returned when blocked.</summary>
    public int BlockStatusCode { get; set; } = 403;

    /// <summary>Always show full detection details in the response.</summary>
    public bool IncludeDetailsInResponse { get; set; } = true;

    public bool EnableProxyHeaderDetection { get; set; } = true;
    public bool EnableTlsCertificateDetection { get; set; } = true;
    public bool EnableHeaderAnomalyDetection { get; set; } = true;
    public bool EnableUserAgentAnalysis { get; set; } = true;
    public bool EnableTimingAnalysis { get; set; } = true;
    public bool EnableCollaboratorDetection { get; set; } = true;
    public bool EnableRepeaterIntruderDetection { get; set; } = true;

    /// <summary>Paths to exclude from detection.</summary>
    public List<string> ExcludedPaths { get; set; } = ["/health", "/ready"];
}
