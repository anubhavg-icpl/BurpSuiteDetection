# BurpSuiteDetection

ASP.NET Core middleware that detects and blocks requests originating from **Burp Suite** and other proxy-based security testing tools. When a proxied request hits your API, the middleware scores it across 7 detection layers and responds with a clear **"BURP SUITE DETECTED"** message.

## Detection Layers

| # | Layer | What it catches | Score |
|---|-------|----------------|-------|
| 1 | **Proxy Headers** | `Proxy-Connection`, `Proxy-Authorization`, `X-Burp-Customheader` — headers browsers never send | 20-30 |
| 2 | **TLS Certificate** | PortSwigger CA in client certificate issuer/subject (Burp MITM cert) | 50 |
| 3 | **Header Anomalies** | Localhost forwarding headers, `Content-Length: 0` on GET, `Connection: close`, HTTP request smuggling probes (`Transfer-Encoding` + `Content-Length`) | 5-25 |
| 4 | **User-Agent Analysis** | Burp identifiers, missing/empty UA, scanner strings (sqlmap, nikto, nuclei, etc.), `Sec-CH-UA` mismatch for modern Chrome | 15-40 |
| 5 | **Timing Analysis** | Stale `Date` header from Burp intercept hold | 15 |
| 6 | **Collaborator Detection** | Burp Collaborator / OAST domains in headers, query strings, and URL paths | 40 |
| 7 | **Repeater / Intruder** | Intruder `§` payload markers, fuzzing payload patterns (SQLi, XSS, path traversal) | 20-35 |

Scores accumulate. If the total meets the threshold (default: 30), the request is **blocked with 403** and the detection details are returned.

## Quick Start

```bash
# Clone
git clone https://github.com/anubhavg-icpl/BurpSuiteDetection.git
cd BurpSuiteDetection

# Run
dotnet run --project BurpSuiteDetection

# Test with a clean request (passes through)
curl http://localhost:5010/api/weatherforecast

# Simulate Burp Suite request (gets blocked)
curl -H "Proxy-Connection: keep-alive" -H "User-Agent: BurpSuite/2024" \
     http://localhost:5010/api/weatherforecast
```

### Blocked Response Example

```json
{
  "detected": true,
  "message": "BURP SUITE DETECTED",
  "threatScore": 90,
  "riskLevel": "CRITICAL",
  "clientIp": "127.0.0.1",
  "indicators": [
    "[PROXY] Burp-specific header present: Proxy-Connection=keep-alive",
    "[PROXY] Proxy-Connection header (classic Burp Suite signature)",
    "[UA] User-Agent contains Burp identifier: 'BurpSuite'"
  ],
  "timestamp": "2026-03-20T05:30:00+00:00"
}
```

### Console Output

```
============================================
    BURP SUITE DETECTED
============================================
  IP       : 127.0.0.1
  Method   : GET
  Path     : /api/weatherforecast
  Score    : 90/100  (CRITICAL)
  Indicators:
    - [PROXY] Burp-specific header present: Proxy-Connection=keep-alive
    - [UA] User-Agent contains Burp identifier: 'BurpSuite'
============================================
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/weatherforecast` | Demo API endpoint (protected by middleware) |
| `GET /api/security/check` | Returns detection analysis for the current request |
| `GET /health` | Health check (excluded from detection) |

## Configuration

All settings are in `appsettings.json` under the `BurpDetection` section:

```json
{
  "BurpDetection": {
    "BlockingThreshold": 30,
    "BlockRequests": true,
    "BlockStatusCode": 403,
    "IncludeDetailsInResponse": true,
    "EnableProxyHeaderDetection": true,
    "EnableTlsCertificateDetection": true,
    "EnableHeaderAnomalyDetection": true,
    "EnableUserAgentAnalysis": true,
    "EnableTimingAnalysis": true,
    "EnableCollaboratorDetection": true,
    "EnableRepeaterIntruderDetection": true,
    "ExcludedPaths": ["/health", "/ready"]
  }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `BlockingThreshold` | 30 | Min score (0-100) to trigger detection |
| `BlockRequests` | true | Block detected requests (`false` = log only) |
| `BlockStatusCode` | 403 | HTTP status code for blocked requests |
| `IncludeDetailsInResponse` | true | Return indicators in response body |
| `Enable*` | true | Toggle individual detection layers |
| `ExcludedPaths` | health, ready | Paths that skip detection |

## Integration Into Your Project

Add the middleware to any ASP.NET Core API:

```csharp
// Program.cs
builder.Services.AddBurpDetection(builder.Configuration);

var app = builder.Build();
app.UseBurpDetection(); // Add early in the pipeline
```

## Running Tests

```bash
dotnet test
```

**46 tests** covering all detection layers — unit tests for each detector and integration tests with `WebApplicationFactory` for end-to-end validation.

## Project Structure

```
BurpSuiteDetection/
├── Middleware/
│   └── BurpDetectionMiddleware.cs   # Pipeline middleware + DI extensions
├── Models/
│   ├── BurpDetectionOptions.cs      # Configuration model
│   └── BurpDetectionResult.cs       # Detection result with score + message
├── Services/
│   └── BurpDetectionService.cs      # Core 7-layer detection engine
└── Program.cs                       # API setup + endpoints

BurpSuiteDetection.Tests/
├── BurpDetectionServiceTests.cs     # Unit tests (all detection layers)
└── IntegrationTests.cs              # End-to-end HTTP tests
```

## Tech Stack

- .NET 10 / ASP.NET Core
- xUnit + WebApplicationFactory

## License

MIT
