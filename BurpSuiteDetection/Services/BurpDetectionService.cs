using System.Text.RegularExpressions;
using BurpSuiteDetection.Models;
using Microsoft.Extensions.Options;

namespace BurpSuiteDetection.Services;

public sealed partial class BurpDetectionService
{
    private readonly BurpDetectionOptions _options;
    private readonly ILogger<BurpDetectionService> _logger;

    // --- Direct Burp / proxy headers (browsers NEVER send these) ---
    private static readonly HashSet<string> BurpSpecificHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Proxy-Connection",
        "Proxy-Authorization",
        "X-Burp-Customheader",
        "X-Burp-Api-Key",
    };

    // --- Headers Burp injects / modifies when proxying ---
    private static readonly HashSet<string> ProxyForwardingHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
        "X-Forwarded-Port",
        "X-Original-URL",
        "X-Rewrite-URL",
        "Via",
        "Forwarded",
    };

    // --- PortSwigger CA identifiers (TLS MITM cert) ---
    private static readonly string[] BurpCaCertIndicators =
    [
        "PortSwigger",
        "Burp",
        "PortSwigger CA",
        "BurpSuite",
    ];

    // --- User-Agent strings Burp tools send by default ---
    private static readonly string[] BurpUserAgentPatterns =
    [
        "Burp",
        "burp",
        "PortSwigger",
        "BurpSuite",
        "burpsuite",
    ];

    // --- Burp Collaborator domain patterns ---
    private static readonly string[] CollaboratorPatterns =
    [
        ".burpcollaborator.net",
        ".oastify.com",
        ".oast.pro",
        ".oast.live",
        ".oast.site",
        ".oast.online",
        ".oast.fun",
        ".oast.me",
        ".interact.sh",
    ];

    public BurpDetectionService(
        IOptions<BurpDetectionOptions> options,
        ILogger<BurpDetectionService> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public BurpDetectionResult Analyze(HttpContext context)
    {
        var indicators = new List<string>();
        int score = 0;

        if (_options.EnableProxyHeaderDetection)
            score += DetectProxyHeaders(context, indicators);

        if (_options.EnableTlsCertificateDetection)
            score += DetectBurpCertificate(context, indicators);

        if (_options.EnableHeaderAnomalyDetection)
            score += DetectHeaderAnomalies(context, indicators);

        if (_options.EnableUserAgentAnalysis)
            score += DetectUserAgentAnomalies(context, indicators);

        if (_options.EnableTimingAnalysis)
            score += DetectTimingAnomalies(context, indicators);

        if (_options.EnableCollaboratorDetection)
            score += DetectBurpCollaborator(context, indicators);

        if (_options.EnableRepeaterIntruderDetection)
            score += DetectRepeaterIntruderPatterns(context, indicators);

        score = Math.Min(score, 100);

        var result = new BurpDetectionResult
        {
            IsDetected = score >= _options.BlockingThreshold,
            ThreatScore = score,
            Indicators = indicators,
            ClientIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            RequestPath = context.Request.Path,
            RequestMethod = context.Request.Method,
            Timestamp = DateTimeOffset.UtcNow,
        };

        return result;
    }

    // ────────────────────────────────────────────────────────────
    //  1. PROXY HEADER DETECTION
    // ────────────────────────────────────────────────────────────
    private int DetectProxyHeaders(HttpContext context, List<string> indicators)
    {
        int score = 0;
        var headers = context.Request.Headers;

        // Direct Burp-specific headers — highest confidence
        foreach (var header in BurpSpecificHeaders)
        {
            if (!headers.ContainsKey(header)) continue;

            indicators.Add($"[PROXY] Burp-specific header present: {header}={headers[header]}");
            score += 30;
        }

        // Proxy-Connection is the #1 Burp tell — no browser ever sends it
        if (headers.ContainsKey("Proxy-Connection"))
        {
            indicators.Add("[PROXY] Proxy-Connection header (classic Burp Suite signature — browsers never send this)");
            score += 20;
        }

        return score;
    }

    // ────────────────────────────────────────────────────────────
    //  2. TLS CERTIFICATE DETECTION (PortSwigger CA)
    // ────────────────────────────────────────────────────────────
    private int DetectBurpCertificate(HttpContext context, List<string> indicators)
    {
        int score = 0;

        var clientCert = context.Connection.ClientCertificate;
        if (clientCert is null)
            return score;

        var issuer = clientCert.Issuer;
        var subject = clientCert.Subject;

        foreach (var indicator in BurpCaCertIndicators)
        {
            if (issuer.Contains(indicator, StringComparison.OrdinalIgnoreCase))
            {
                indicators.Add($"[TLS] Certificate issuer matches Burp CA: {issuer}");
                score += 50;
                return score;
            }

            if (subject.Contains(indicator, StringComparison.OrdinalIgnoreCase))
            {
                indicators.Add($"[TLS] Certificate subject matches Burp CA: {subject}");
                score += 50;
                return score;
            }
        }

        return score;
    }

    // ────────────────────────────────────────────────────────────
    //  3. HEADER ANOMALY DETECTION
    // ────────────────────────────────────────────────────────────
    private int DetectHeaderAnomalies(HttpContext context, List<string> indicators)
    {
        int score = 0;
        var headers = context.Request.Headers;

        // 3a. Forwarding headers pointing to localhost (Burp runs locally)
        foreach (var header in ProxyForwardingHeaders)
        {
            if (!headers.TryGetValue(header, out var values)) continue;
            var value = values.ToString();

            if (IsLocalhostValue(value))
            {
                indicators.Add($"[HEADER] Forwarding header '{header}' points to localhost: {value}");
                score += 20;
            }
        }

        // 3b. Duplicate Host headers (Burp misconfiguration quirk)
        if (headers["Host"].Count > 1)
        {
            indicators.Add("[HEADER] Multiple Host headers detected");
            score += 15;
        }

        // 3c. Content-Length: 0 on GET/HEAD (Burp adds this; browsers don't)
        if ((context.Request.Method is "GET" or "HEAD")
            && headers.ContainsKey("Content-Length")
            && headers["Content-Length"].ToString() == "0")
        {
            indicators.Add("[HEADER] Content-Length: 0 on GET request (Burp signature)");
            score += 15;
        }

        // 3d. Accept-Encoding missing or set to "identity" (Burp Repeater default)
        if (headers.TryGetValue("Accept-Encoding", out var acceptEnc))
        {
            var enc = acceptEnc.ToString();
            if (string.IsNullOrWhiteSpace(enc) || enc == "identity")
            {
                indicators.Add($"[HEADER] Unusual Accept-Encoding: '{enc}' (Burp Repeater default)");
                score += 10;
            }
        }

        // 3e. Accept header exactly "*/*" (Burp Repeater/Intruder default)
        if (headers.TryGetValue("Accept", out var accept))
        {
            if (accept.ToString().Trim() == "*/*")
            {
                indicators.Add("[HEADER] Accept: */* (default Burp Repeater value)");
                score += 5;
            }
        }

        // 3f. Connection: close (Burp default — browsers use keep-alive)
        if (headers.TryGetValue("Connection", out var connection))
        {
            if (connection.ToString().Equals("close", StringComparison.OrdinalIgnoreCase))
            {
                indicators.Add("[HEADER] Connection: close (Burp default, browsers use keep-alive)");
                score += 10;
            }
        }

        // 3g. Non-standard header casing (underscores, mixed case)
        var rawHeaderNames = headers.Keys.ToList();
        int nonStandardCount = rawHeaderNames.Count(h => h.Contains('_') || HasMixedNonStandardCasing(h));
        if (nonStandardCount > 2)
        {
            indicators.Add($"[HEADER] {nonStandardCount} headers with non-standard casing");
            score += 10;
        }

        // 3h. Transfer-Encoding + Content-Length together (request smuggling probe)
        if (headers.ContainsKey("Transfer-Encoding") && headers.ContainsKey("Content-Length"))
        {
            indicators.Add("[HEADER] Both Transfer-Encoding and Content-Length present (HTTP smuggling probe)");
            score += 25;
        }

        return score;
    }

    // ────────────────────────────────────────────────────────────
    //  4. USER-AGENT ANALYSIS
    // ────────────────────────────────────────────────────────────
    private int DetectUserAgentAnomalies(HttpContext context, List<string> indicators)
    {
        int score = 0;
        var headers = context.Request.Headers;

        if (!headers.TryGetValue("User-Agent", out var userAgentValues))
        {
            indicators.Add("[UA] Missing User-Agent header (all browsers send one)");
            score += 20;
            return score;
        }

        var userAgent = userAgentValues.ToString();

        if (string.IsNullOrWhiteSpace(userAgent))
        {
            indicators.Add("[UA] Empty User-Agent header");
            score += 20;
            return score;
        }

        // Explicit Burp identifiers in User-Agent
        foreach (var pattern in BurpUserAgentPatterns)
        {
            if (!userAgent.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

            indicators.Add($"[UA] User-Agent contains Burp identifier: '{pattern}' → full UA: {userAgent}");
            score += 40;
            return score;
        }

        // Known security scanner / fuzzer User-Agents
        if (ScannerUserAgentRegex().IsMatch(userAgent))
        {
            indicators.Add($"[UA] Security scanner User-Agent detected: {userAgent}");
            score += 25;
        }

        // Sec-CH-UA consistency — Burp doesn't always sync these with User-Agent
        if (headers.TryGetValue("Sec-CH-UA", out var secChUa))
        {
            var secStr = secChUa.ToString();
            if (userAgent.Contains("Chrome", StringComparison.OrdinalIgnoreCase)
                && !secStr.Contains("Chromium", StringComparison.OrdinalIgnoreCase)
                && !secStr.Contains("Chrome", StringComparison.OrdinalIgnoreCase))
            {
                indicators.Add("[UA] User-Agent claims Chrome but Sec-CH-UA disagrees (Burp header mismatch)");
                score += 15;
            }
        }
        // No Sec-CH-UA at all but User-Agent claims modern Chrome (Chrome 89+ always sends it)
        else if (ChromeVersionRegex().Match(userAgent) is { Success: true } m
                 && int.TryParse(m.Groups[1].Value, out int chromeVer)
                 && chromeVer >= 89)
        {
            indicators.Add($"[UA] Claims Chrome/{chromeVer} but missing Sec-CH-UA (Burp doesn't add client hints)");
            score += 15;
        }

        return score;
    }

    // ────────────────────────────────────────────────────────────
    //  5. TIMING ANALYSIS
    // ────────────────────────────────────────────────────────────
    private int DetectTimingAnomalies(HttpContext context, List<string> indicators)
    {
        int score = 0;

        // Date header drift (Burp intercept holds requests, causing stale dates)
        if (context.Request.Headers.TryGetValue("Date", out var dateHeader)
            && DateTimeOffset.TryParse(dateHeader.ToString(), out var requestDate))
        {
            var drift = DateTimeOffset.UtcNow - requestDate;
            if (drift.TotalSeconds > 30)
            {
                indicators.Add($"[TIMING] Request Date header drifted {drift.TotalSeconds:F1}s (Burp intercept hold)");
                score += 15;
            }
        }

        return score;
    }

    // ────────────────────────────────────────────────────────────
    //  6. BURP COLLABORATOR DETECTION
    // ────────────────────────────────────────────────────────────
    private int DetectBurpCollaborator(HttpContext context, List<string> indicators)
    {
        int score = 0;

        // Scan all header values for Collaborator/OOB domains
        foreach (var header in context.Request.Headers)
        {
            var value = header.Value.ToString();
            foreach (var domain in CollaboratorPatterns)
            {
                if (!value.Contains(domain, StringComparison.OrdinalIgnoreCase)) continue;

                indicators.Add($"[COLLABORATOR] Burp Collaborator domain found in header '{header.Key}': {domain}");
                score += 40;
                return score;
            }
        }

        // Scan query string for Collaborator payloads
        var queryString = context.Request.QueryString.Value ?? string.Empty;
        foreach (var domain in CollaboratorPatterns)
        {
            if (!queryString.Contains(domain, StringComparison.OrdinalIgnoreCase)) continue;

            indicators.Add($"[COLLABORATOR] Burp Collaborator domain in query string: {domain}");
            score += 40;
            return score;
        }

        // Scan request path
        var path = context.Request.Path.Value ?? string.Empty;
        foreach (var domain in CollaboratorPatterns)
        {
            if (!path.Contains(domain, StringComparison.OrdinalIgnoreCase)) continue;

            indicators.Add($"[COLLABORATOR] Burp Collaborator domain in URL path: {domain}");
            score += 40;
            return score;
        }

        return score;
    }

    // ────────────────────────────────────────────────────────────
    //  7. REPEATER / INTRUDER / SCANNER PATTERN DETECTION
    // ────────────────────────────────────────────────────────────
    private int DetectRepeaterIntruderPatterns(HttpContext context, List<string> indicators)
    {
        int score = 0;
        var headers = context.Request.Headers;

        // Burp Intruder uses § markers; sometimes they leak into header values
        foreach (var header in headers)
        {
            var value = header.Value.ToString();
            if (value.Contains('\xa7') || value.Contains("§"))
            {
                indicators.Add($"[INTRUDER] Burp Intruder payload marker '§' found in header '{header.Key}'");
                score += 35;
                return score;
            }
        }

        // Check query string for § markers
        var queryString = context.Request.QueryString.Value ?? string.Empty;
        if (queryString.Contains('\xa7') || queryString.Contains("§"))
        {
            indicators.Add("[INTRUDER] Burp Intruder payload marker '§' found in query string");
            score += 35;
            return score;
        }

        // Burp Scanner fuzzing patterns — common injection test strings
        var suspiciousPayloads = new[]
        {
            "'-\"", "{{", "}}", "${", "<script>", "javascript:", "onerror=",
            "SLEEP(", "WAITFOR", "1 OR 1=1", "' OR '1'='1", "1;SELECT",
            "../../../", "..\\..\\",
        };

        foreach (var header in headers)
        {
            var value = header.Value.ToString();
            int payloadHits = suspiciousPayloads.Count(p =>
                value.Contains(p, StringComparison.OrdinalIgnoreCase));

            if (payloadHits < 2) continue;

            indicators.Add($"[SCANNER] Multiple fuzzing payloads in header '{header.Key}' ({payloadHits} patterns)");
            score += 20;
            break;
        }

        // Check for rapid sequential payload variations in query params
        // (Burp Intruder sends many requests with incremental param changes)
        if (queryString.Length > 0)
        {
            int qsPayloadHits = suspiciousPayloads.Count(p =>
                queryString.Contains(p, StringComparison.OrdinalIgnoreCase));
            if (qsPayloadHits >= 2)
            {
                indicators.Add($"[SCANNER] Multiple fuzzing payloads in query string ({qsPayloadHits} patterns)");
                score += 20;
            }
        }

        return score;
    }

    // ────────────────────────────────────────────────────────────
    //  HELPERS
    // ────────────────────────────────────────────────────────────

    private static bool IsLocalhostValue(string value)
    {
        return value.Contains("127.0.0.1", StringComparison.Ordinal)
            || value.Contains("::1", StringComparison.Ordinal)
            || value.Contains("localhost", StringComparison.OrdinalIgnoreCase)
            || value.Contains("0.0.0.0", StringComparison.Ordinal);
    }

    private static bool HasMixedNonStandardCasing(string headerName)
    {
        if (string.IsNullOrEmpty(headerName)) return false;
        var parts = headerName.Split('-');
        return parts.Any(p => p.Length > 0 && char.IsLower(p[0]) && p.Any(char.IsUpper));
    }

    [GeneratedRegex(
        @"(nikto|sqlmap|nmap|dirbuster|gobuster|wfuzz|ffuf|nuclei|httpx|zaproxy|zap|w3af|arachni|skipfish|havij|acunetix|nessus|openvas|qualys|masscan|amass|subfinder|feroxbuster|whatweb|wpscan|joomscan|commix|tplmap|dalfox|xsstrike|arjun|paramspider)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex ScannerUserAgentRegex();

    [GeneratedRegex(@"Chrome/(\d+)", RegexOptions.Compiled)]
    private static partial Regex ChromeVersionRegex();
}
