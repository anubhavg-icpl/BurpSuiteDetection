using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace BurpSuiteDetection.Tests;

public class IntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public IntegrationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    // ── CLEAN REQUESTS PASS THROUGH ──

    [Fact]
    public async Task HealthEndpoint_IsExcluded_Returns200()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("healthy", body);
    }

    [Fact]
    public async Task CleanRequest_WeatherForecast_Returns200()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/weatherforecast");
        request.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        request.Headers.Add("Accept", "text/html,application/xhtml+xml");
        request.Headers.Add("Accept-Encoding", "gzip, deflate, br");
        request.Headers.Add("Connection", "keep-alive");

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("no proxy detected", body, StringComparison.OrdinalIgnoreCase);
    }

    // ── BURP SUITE REQUESTS GET BLOCKED ──

    [Fact]
    public async Task BurpUserAgent_Gets403_WithDetectedMessage()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/weatherforecast");
        request.Headers.Add("User-Agent", "Mozilla/5.0 BurpSuite/2024.3");

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("BURP SUITE DETECTED", body);
    }

    [Fact]
    public async Task ProxyConnection_Header_Gets403()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/weatherforecast");
        request.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0)");
        request.Headers.Add("Proxy-Connection", "keep-alive");

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("BURP SUITE DETECTED", body);
    }

    [Fact]
    public async Task Collaborator_Domain_Gets403()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/weatherforecast?cb=https://test.burpcollaborator.net/");
        request.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0)");

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("BURP SUITE DETECTED", body);
    }

    [Fact]
    public async Task FullBurpRequest_Gets403_WithAllIndicators()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/weatherforecast");
        request.Headers.Add("User-Agent", "Mozilla/5.0 BurpSuite/2024");
        request.Headers.Add("Proxy-Connection", "keep-alive");
        request.Headers.Add("X-Forwarded-For", "127.0.0.1");
        request.Headers.Add("Connection", "close");

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("BURP SUITE DETECTED", body);
        Assert.Contains("indicators", body);
    }

    // ── SECURITY CHECK ENDPOINT ──

    [Fact]
    public async Task SecurityCheck_Clean_Request_Shows_NotDetected()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/security/check");
        request.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        request.Headers.Add("Accept-Encoding", "gzip, deflate, br");
        request.Headers.Add("Connection", "keep-alive");

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("No proxy tool detected", body);
    }

    // ── SCANNER USER AGENTS ──

    [Theory]
    [InlineData("sqlmap/1.6.12")]
    [InlineData("Nikto/2.1.6")]
    [InlineData("gobuster/3.5")]
    public async Task Scanner_UserAgents_GetBlocked(string userAgent)
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/weatherforecast");
        request.Headers.Add("User-Agent", userAgent);

        var response = await client.SendAsync(request);

        // Scanner UAs score 25 which is >= dev threshold of 20
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
}
