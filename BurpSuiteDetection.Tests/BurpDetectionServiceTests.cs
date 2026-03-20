using BurpSuiteDetection.Models;
using BurpSuiteDetection.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace BurpSuiteDetection.Tests;

public class BurpDetectionServiceTests
{
    private static BurpDetectionService CreateService(Action<BurpDetectionOptions>? configure = null)
    {
        var options = new BurpDetectionOptions();
        configure?.Invoke(options);
        return new BurpDetectionService(
            Options.Create(options),
            NullLogger<BurpDetectionService>.Instance);
    }

    private static HttpContext CreateContext(Action<HttpContext>? setup = null)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "GET";
        context.Request.Path = "/api/test";
        context.Request.Headers["Host"] = "localhost";
        context.Request.Headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        setup?.Invoke(context);
        return context;
    }

    // ── PROXY HEADER DETECTION ──

    [Fact]
    public void Detects_ProxyConnection_Header()
    {
        var service = CreateService();
        var context = CreateContext(ctx =>
            ctx.Request.Headers["Proxy-Connection"] = "keep-alive");

        var result = service.Analyze(context);

        Assert.True(result.ThreatScore > 0);
        Assert.Contains(result.Indicators, i => i.Contains("Proxy-Connection"));
    }

    [Fact]
    public void Detects_ProxyAuthorization_Header()
    {
        var service = CreateService();
        var context = CreateContext(ctx =>
            ctx.Request.Headers["Proxy-Authorization"] = "Basic dGVzdDp0ZXN0");

        var result = service.Analyze(context);

        Assert.True(result.ThreatScore > 0);
        Assert.Contains(result.Indicators, i => i.Contains("Proxy-Authorization"));
    }

    [Fact]
    public void Detects_XBurpCustomheader()
    {
        var service = CreateService();
        var context = CreateContext(ctx =>
            ctx.Request.Headers["X-Burp-Customheader"] = "test");

        var result = service.Analyze(context);

        Assert.True(result.ThreatScore >= 30);
        Assert.Contains(result.Indicators, i => i.Contains("X-Burp-Customheader"));
    }

    // ── USER-AGENT DETECTION ──

    [Theory]
    [InlineData("Burp Suite Professional")]
    [InlineData("Mozilla/5.0 BurpSuite/2024.1")]
    [InlineData("PortSwigger Scanner")]
    public void Detects_BurpSuite_UserAgent(string userAgent)
    {
        var service = CreateService();
        var context = CreateContext(ctx =>
            ctx.Request.Headers["User-Agent"] = userAgent);

        var result = service.Analyze(context);

        Assert.True(result.ThreatScore >= 40);
        Assert.Contains(result.Indicators, i => i.Contains("[UA]"));
    }

    [Fact]
    public void Detects_Missing_UserAgent()
    {
        var service = CreateService();
        var context = CreateContext(ctx =>
            ctx.Request.Headers.Remove("User-Agent"));

        var result = service.Analyze(context);

        Assert.True(result.ThreatScore > 0);
        Assert.Contains(result.Indicators, i => i.Contains("Missing User-Agent"));
    }

    [Fact]
    public void Detects_Empty_UserAgent()
    {
        var service = CreateService();
        var context = CreateContext(ctx =>
            ctx.Request.Headers["User-Agent"] = "");

        var result = service.Analyze(context);

        Assert.True(result.ThreatScore > 0);
        Assert.Contains(result.Indicators, i => i.Contains("Empty User-Agent"));
    }

    [Theory]
    [InlineData("sqlmap/1.6")]
    [InlineData("Nikto/2.1.6")]
    [InlineData("gobuster/3.1.0")]
    [InlineData("nuclei - projectdiscovery")]
    public void Detects_Scanner_UserAgents(string userAgent)
    {
        var service = CreateService();
        var context = CreateContext(ctx =>
            ctx.Request.Headers["User-Agent"] = userAgent);

        var result = service.Analyze(context);

        Assert.True(result.ThreatScore > 0);
        Assert.Contains(result.Indicators, i => i.Contains("[UA]"));
    }

    // ── HEADER ANOMALY DETECTION ──

    [Theory]
    [InlineData("X-Forwarded-For", "127.0.0.1")]
    [InlineData("X-Forwarded-For", "localhost")]
    [InlineData("Forwarded", "for=127.0.0.1")]
    [InlineData("Via", "1.1 localhost")]
    public void Detects_Localhost_Forwarding_Headers(string header, string value)
    {
        var service = CreateService();
        var context = CreateContext(ctx =>
            ctx.Request.Headers[header] = value);

        var result = service.Analyze(context);

        Assert.True(result.ThreatScore > 0);
        Assert.Contains(result.Indicators, i => i.Contains("[HEADER]") && i.Contains("localhost"));
    }

    [Fact]
    public void Detects_ContentLength_Zero_On_GET()
    {
        var service = CreateService();
        var context = CreateContext(ctx =>
        {
            ctx.Request.Method = "GET";
            ctx.Request.Headers["Content-Length"] = "0";
        });

        var result = service.Analyze(context);

        Assert.Contains(result.Indicators, i => i.Contains("Content-Length: 0 on GET"));
    }

    [Fact]
    public void Detects_Connection_Close()
    {
        var service = CreateService();
        var context = CreateContext(ctx =>
            ctx.Request.Headers["Connection"] = "close");

        var result = service.Analyze(context);

        Assert.Contains(result.Indicators, i => i.Contains("Connection: close"));
    }

    [Fact]
    public void Detects_TransferEncoding_ContentLength_Smuggling()
    {
        var service = CreateService();
        var context = CreateContext(ctx =>
        {
            ctx.Request.Headers["Transfer-Encoding"] = "chunked";
            ctx.Request.Headers["Content-Length"] = "0";
        });

        var result = service.Analyze(context);

        Assert.Contains(result.Indicators, i => i.Contains("smuggling"));
    }

    // ── COLLABORATOR DETECTION ──

    [Theory]
    [InlineData("Referer", "https://abc123.burpcollaborator.net/")]
    [InlineData("X-Custom", "https://test.oastify.com/callback")]
    [InlineData("Origin", "https://payload.oast.pro")]
    public void Detects_Collaborator_In_Headers(string header, string value)
    {
        var service = CreateService();
        var context = CreateContext(ctx =>
            ctx.Request.Headers[header] = value);

        var result = service.Analyze(context);

        Assert.True(result.ThreatScore >= 40);
        Assert.Contains(result.Indicators, i => i.Contains("[COLLABORATOR]"));
    }

    [Fact]
    public void Detects_Collaborator_In_QueryString()
    {
        var service = CreateService();
        var context = CreateContext(ctx =>
            ctx.Request.QueryString = new QueryString("?callback=https://x.burpcollaborator.net/"));

        var result = service.Analyze(context);

        Assert.True(result.ThreatScore >= 40);
        Assert.Contains(result.Indicators, i => i.Contains("[COLLABORATOR]") && i.Contains("query string"));
    }

    // ── REPEATER / INTRUDER DETECTION ──

    [Fact]
    public void Detects_Intruder_Payload_Marker_In_Header()
    {
        var service = CreateService();
        var context = CreateContext(ctx =>
            ctx.Request.Headers["X-Custom"] = "test\xa7payload\xa7value");

        var result = service.Analyze(context);

        Assert.True(result.ThreatScore > 0);
        Assert.Contains(result.Indicators, i => i.Contains("[INTRUDER]"));
    }

    [Fact]
    public void Detects_Fuzzing_Payloads_In_QueryString()
    {
        var service = CreateService();
        var context = CreateContext(ctx =>
            ctx.Request.QueryString = new QueryString("?id=1 OR 1=1&name=<script>alert(1)</script>"));

        var result = service.Analyze(context);

        Assert.True(result.ThreatScore > 0);
        Assert.Contains(result.Indicators, i => i.Contains("[SCANNER]"));
    }

    // ── TIMING ANALYSIS ──

    [Fact]
    public void Detects_Stale_Date_Header()
    {
        var service = CreateService();
        var staleDate = DateTimeOffset.UtcNow.AddMinutes(-5).ToString("R");
        var context = CreateContext(ctx =>
            ctx.Request.Headers["Date"] = staleDate);

        var result = service.Analyze(context);

        Assert.Contains(result.Indicators, i => i.Contains("[TIMING]") && i.Contains("drifted"));
    }

    // ── CLEAN REQUEST PASSES THROUGH ──

    [Fact]
    public void Clean_Browser_Request_Has_Zero_Score()
    {
        var service = CreateService();
        var context = CreateContext(ctx =>
        {
            ctx.Request.Headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
            ctx.Request.Headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            ctx.Request.Headers["Accept-Encoding"] = "gzip, deflate, br";
            ctx.Request.Headers["Accept-Language"] = "en-US,en;q=0.9";
            ctx.Request.Headers["Connection"] = "keep-alive";
            // Real Chrome 120 always sends Sec-CH-UA
            ctx.Request.Headers["Sec-CH-UA"] = "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"";
        });

        var result = service.Analyze(context);

        Assert.Equal(0, result.ThreatScore);
        Assert.False(result.IsDetected);
        Assert.Equal("No proxy tool detected", result.Message);
        Assert.Empty(result.Indicators);
    }

    // ── DETECTION RESULT MODEL ──

    [Fact]
    public void Detected_Result_Shows_BurpSuiteDetected_Message()
    {
        var service = CreateService(o => o.BlockingThreshold = 30);
        var context = CreateContext(ctx =>
        {
            ctx.Request.Headers["Proxy-Connection"] = "keep-alive";
            ctx.Request.Headers["User-Agent"] = "BurpSuite/2024";
        });

        var result = service.Analyze(context);

        Assert.True(result.IsDetected);
        Assert.Equal("BURP SUITE DETECTED", result.Message);
        Assert.True(result.ThreatScore >= 30);
    }

    [Theory]
    [InlineData(80, "CRITICAL")]
    [InlineData(60, "HIGH")]
    [InlineData(40, "MEDIUM")]
    [InlineData(20, "LOW")]
    [InlineData(0, "NONE")]
    public void RiskLevel_Maps_Correctly(int score, string expectedLevel)
    {
        var result = new BurpDetectionResult { ThreatScore = score };
        Assert.Equal(expectedLevel, result.RiskLevel);
    }

    // ── OPTIONS / CONFIG ──

    [Fact]
    public void Disabled_Detectors_Produce_No_Score()
    {
        var service = CreateService(o =>
        {
            o.EnableProxyHeaderDetection = false;
            o.EnableTlsCertificateDetection = false;
            o.EnableHeaderAnomalyDetection = false;
            o.EnableUserAgentAnalysis = false;
            o.EnableTimingAnalysis = false;
            o.EnableCollaboratorDetection = false;
            o.EnableRepeaterIntruderDetection = false;
        });

        var context = CreateContext(ctx =>
        {
            ctx.Request.Headers["Proxy-Connection"] = "keep-alive";
            ctx.Request.Headers["User-Agent"] = "BurpSuite/2024";
        });

        var result = service.Analyze(context);

        Assert.Equal(0, result.ThreatScore);
        Assert.False(result.IsDetected);
    }

    // ── COMBINED ATTACK SIMULATION ──

    [Fact]
    public void Full_BurpSuite_Request_Gets_Maximum_Detection()
    {
        var service = CreateService(o => o.BlockingThreshold = 30);
        var context = CreateContext(ctx =>
        {
            ctx.Request.Headers["Proxy-Connection"] = "keep-alive";
            ctx.Request.Headers["User-Agent"] = "Mozilla/5.0 BurpSuite/2024.3";
            ctx.Request.Headers["X-Forwarded-For"] = "127.0.0.1";
            ctx.Request.Headers["Connection"] = "close";
            ctx.Request.Headers["Accept"] = "*/*";
            ctx.Request.Headers["Content-Length"] = "0";
            ctx.Request.Headers["Referer"] = "https://xyz.burpcollaborator.net/";
        });

        var result = service.Analyze(context);

        Assert.True(result.IsDetected);
        Assert.Equal("BURP SUITE DETECTED", result.Message);
        Assert.True(result.ThreatScore >= 80);
        Assert.Equal("CRITICAL", result.RiskLevel);
        Assert.True(result.Indicators.Count >= 4);
    }

    // ── SEC-CH-UA MISMATCH ──

    [Fact]
    public void Detects_Missing_SecChUA_For_Modern_Chrome()
    {
        var service = CreateService();
        var context = CreateContext(ctx =>
        {
            ctx.Request.Headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
            // No Sec-CH-UA header — Chrome 120 always sends this
        });

        var result = service.Analyze(context);

        Assert.Contains(result.Indicators, i => i.Contains("Sec-CH-UA") && i.Contains("Chrome/120"));
    }
}
