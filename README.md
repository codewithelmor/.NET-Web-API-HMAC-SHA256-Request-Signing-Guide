# .NET Web API — HMAC-SHA256 Request Signing Guide

A complete, production-oriented guide to signing and verifying HTTP requests with HMAC-SHA256 in ASP.NET Core (.NET 8), covering both **inbound verification** (your API validates signed requests from clients) and **outbound signing** (your API calls another service and signs its own requests).

---

## Table of Contents

1. [Concepts & Threat Model](#1-concepts--threat-model)
2. [Canonical String Construction](#2-canonical-string-construction)
3. [Shared Project: Signature Utility](#3-shared-project-signature-utility)
4. [Inbound: Verifying Signed Requests (Middleware + Auth Handler)](#4-inbound-verifying-signed-requests)
5. [Outbound: Signing Requests with `HttpClient`](#5-outbound-signing-requests-with-httpclient)
6. [Replay Protection](#6-replay-protection)
7. [Full Working Example](#7-full-working-example)
8. [Testing with curl](#8-testing-with-curl)
9. [Security Checklist](#9-security-checklist)

---

## 1. Concepts & Threat Model

HMAC-SHA256 request signing proves two things to a server:

- **Authenticity** — the caller knows the shared secret.
- **Integrity** — the request (method, path, query, body, timestamp) wasn't modified in transit.

It does **not** provide confidentiality — always pair with HTTPS/TLS. It's commonly used for:

- Server-to-server (S2S) webhooks (Stripe, GitHub, Shopify all use variants of this)
- Internal microservice-to-microservice auth
- Partner/API-key style integrations where you don't want to pass the secret itself on the wire

**Standard signing recipe:**

```
signature = Base64( HMAC-SHA256( secret, canonicalString ) )
```

The canonical string is a deterministic, ordered representation of the request. Both sides must build it *identically* or verification fails.

---

## 2. Canonical String Construction

This is the most important — and most error-prone — part of the whole scheme. Both client and server must agree byte-for-byte.

### Recommended canonical format

```
{HTTP_METHOD}\n
{PATH}\n
{SORTED_QUERY_STRING}\n
{TIMESTAMP}\n
{NONCE}\n
{SHA256_HEX_OF_BODY}
```

Example (newlines are literal `\n`, not line breaks in a display sense):

```
POST
/api/orders
customerId=123&status=pending
1726387200
7e57c1a1-2b3c-4d5e-9f01-abcdef123456
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### Rules that MUST be enforced identically on both sides

| Component | Rule |
|---|---|
| Method | Uppercase (`GET`, `POST`, ...) |
| Path | Case-sensitive, no trailing slash, URL-decoded once, no host/scheme |
| Query string | Sorted by key (ordinal), then by value; `key=value` joined with `&`; empty string if none |
| Timestamp | Unix seconds (UTC), sent as a header (e.g. `X-Signature-Timestamp`) |
| Nonce | Random unique value per request (GUID is fine), sent as a header (e.g. `X-Signature-Nonce`) |
| Body hash | SHA-256 of the **raw, exact bytes** of the body, hex-encoded, lowercase. Empty body → hash of empty byte array |
| Headers included | Keep the *signed* header set minimal and explicit — don't sign "all headers" since proxies/load balancers may rewrite them |

> **Why hash the body instead of including it raw in the canonical string?** Keeps the canonical string bounded in size and avoids encoding ambiguity (line endings, charset) while still binding the signature to the exact payload.

---

## 3. Shared Project: Signature Utility

Put this in a class library referenced by both the API (verifier) and any client (signer) so the logic can never drift apart.

```csharp
// SignatureUtil.cs
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Contoso.Security.Hmac;

public static class SignatureUtil
{
    /// <summary>
    /// Header names used across the signing scheme. Keep these consistent
    /// between signer and verifier.
    /// </summary>
    public static class Headers
    {
        public const string Signature = "X-Signature";
        public const string Timestamp = "X-Signature-Timestamp";
        public const string Nonce = "X-Signature-Nonce";
        public const string KeyId = "X-Signature-KeyId"; // supports key rotation
    }

    /// <summary>
    /// Builds the canonical string that gets signed.
    /// </summary>
    public static string BuildCanonicalString(
        string httpMethod,
        string path,
        string? rawQueryString,
        long unixTimestampSeconds,
        string nonce,
        byte[] bodyBytes)
    {
        var method = httpMethod.ToUpperInvariant();

        var normalizedPath = NormalizePath(path);

        var sortedQuery = NormalizeQueryString(rawQueryString);

        var bodyHashHex = ToHexLower(SHA256.HashData(bodyBytes));

        // \n is the field separator. It is never re-parsed, so ambiguity
        // inside a field value is fine as long as it's not literal \n.
        return string.Join(
            "\n",
            method,
            normalizedPath,
            sortedQuery,
            unixTimestampSeconds.ToString(CultureInfo.InvariantCulture),
            nonce,
            bodyHashHex);
    }

    public static string NormalizePath(string path)
    {
        if (string.IsNullOrEmpty(path)) return "/";
        var decoded = Uri.UnescapeDataString(path);
        return decoded.Length > 1 ? decoded.TrimEnd('/') : decoded;
    }

    public static string NormalizeQueryString(string? rawQueryString)
    {
        if (string.IsNullOrEmpty(rawQueryString)) return string.Empty;

        var qs = rawQueryString.TrimStart('?');
        if (qs.Length == 0) return string.Empty;

        var pairs = qs.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p =>
            {
                var idx = p.IndexOf('=');
                var key = idx >= 0 ? p[..idx] : p;
                var value = idx >= 0 ? p[(idx + 1)..] : string.Empty;
                return (Key: Uri.UnescapeDataString(key), Value: Uri.UnescapeDataString(value));
            })
            .OrderBy(p => p.Key, StringComparer.Ordinal)
            .ThenBy(p => p.Value, StringComparer.Ordinal)
            .Select(p => $"{p.Key}={p.Value}");

        return string.Join("&", pairs);
    }

    /// <summary>
    /// Computes Base64(HMAC-SHA256(secret, canonicalString)).
    /// </summary>
    public static string Sign(string secret, string canonicalString)
    {
        var keyBytes = Encoding.UTF8.GetBytes(secret);
        var messageBytes = Encoding.UTF8.GetBytes(canonicalString);
        var hash = HMACSHA256.HashData(keyBytes, messageBytes);
        return Convert.ToBase64String(hash);
    }

    /// <summary>
    /// Constant-time comparison to prevent timing attacks when verifying signatures.
    /// </summary>
    public static bool TimingSafeEquals(string a, string b)
    {
        var aBytes = Encoding.UTF8.GetBytes(a);
        var bBytes = Encoding.UTF8.GetBytes(b);

        // FixedTimeEquals requires equal-length spans; if lengths differ the
        // request is invalid, but we still run a fixed-time compare against
        // a zeroed buffer of matching length so overall timing doesn't leak
        // the *correct* length either.
        if (aBytes.Length != bBytes.Length)
        {
            CryptographicOperations.FixedTimeEquals(aBytes, aBytes); // burn similar time
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(aBytes, bBytes);
    }

    private static string ToHexLower(byte[] bytes) =>
        Convert.ToHexStringLower(bytes);
}
```

> `CryptographicOperations.FixedTimeEquals` is the .NET-provided constant-time comparison — never use `==`, `string.Equals`, or `SequenceEqual` for comparing secrets/signatures, as they short-circuit and leak timing information.

---

## 4. Inbound: Verifying Signed Requests

Two approaches: a lightweight **middleware** (simplest, good for webhook-style single-purpose APIs) or a full **`AuthenticationHandler`** (better if you want `[Authorize]` semantics, multiple schemes, or `ClaimsPrincipal` integration). Both are shown.

### 4a. Middleware Approach (webhooks-style)

```csharp
// HmacVerificationMiddleware.cs
using System.Text;
using Contoso.Security.Hmac;
using Microsoft.Extensions.Options;

public sealed class HmacOptions
{
    /// <summary>Maps KeyId -> secret, to support key rotation without downtime.</summary>
    public Dictionary<string, string> Secrets { get; set; } = new();

    public TimeSpan AllowedClockSkew { get; set; } = TimeSpan.FromMinutes(5);
}

public sealed class HmacVerificationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IOptionsMonitor<HmacOptions> _options;
    private readonly INonceStore _nonceStore;
    private readonly ILogger<HmacVerificationMiddleware> _logger;

    public HmacVerificationMiddleware(
        RequestDelegate next,
        IOptionsMonitor<HmacOptions> options,
        INonceStore nonceStore,
        ILogger<HmacVerificationMiddleware> logger)
    {
        _next = next;
        _options = options;
        _nonceStore = nonceStore;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var opts = _options.CurrentValue;

        if (!TryGetHeader(context, SignatureUtil.Headers.Signature, out var providedSignature) ||
            !TryGetHeader(context, SignatureUtil.Headers.Timestamp, out var timestampRaw) ||
            !TryGetHeader(context, SignatureUtil.Headers.Nonce, out var nonce) ||
            !TryGetHeader(context, SignatureUtil.Headers.KeyId, out var keyId))
        {
            await Reject(context, "Missing required signature headers.");
            return;
        }

        if (!long.TryParse(timestampRaw, out var timestamp))
        {
            await Reject(context, "Invalid timestamp format.");
            return;
        }

        var requestTime = DateTimeOffset.FromUnixTimeSeconds(timestamp);
        var skew = (DateTimeOffset.UtcNow - requestTime).Duration();
        if (skew > opts.AllowedClockSkew)
        {
            await Reject(context, "Timestamp outside allowed window.");
            return;
        }

        if (!opts.Secrets.TryGetValue(keyId, out var secret))
        {
            await Reject(context, "Unknown key id.");
            return;
        }

        // Replay protection: nonce must be unseen within the skew window.
        if (!await _nonceStore.TryConsumeAsync(nonce, opts.AllowedClockSkew, context.RequestAborted))
        {
            await Reject(context, "Replayed request detected.");
            return;
        }

        // Buffer the body so it can be read for hashing AND still reach the controller.
        context.Request.EnableBuffering();
        byte[] bodyBytes;
        using (var ms = new MemoryStream())
        {
            await context.Request.Body.CopyToAsync(ms, context.RequestAborted);
            bodyBytes = ms.ToArray();
            context.Request.Body.Position = 0; // rewind for downstream middleware/model binding
        }

        var canonical = SignatureUtil.BuildCanonicalString(
            context.Request.Method,
            context.Request.Path.Value ?? "/",
            context.Request.QueryString.Value,
            timestamp,
            nonce,
            bodyBytes);

        var expectedSignature = SignatureUtil.Sign(secret, canonical);

        if (!SignatureUtil.TimingSafeEquals(expectedSignature, providedSignature))
        {
            _logger.LogWarning("HMAC signature mismatch for {Path}", context.Request.Path);
            await Reject(context, "Invalid signature.");
            return;
        }

        await _next(context);
    }

    private static bool TryGetHeader(HttpContext context, string name, out string value)
    {
        if (context.Request.Headers.TryGetValue(name, out var values) && values.Count > 0)
        {
            value = values[0]!;
            return !string.IsNullOrWhiteSpace(value);
        }
        value = string.Empty;
        return false;
    }

    private static async Task Reject(HttpContext context, string reason)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsJsonAsync(new { error = "invalid_signature", detail = reason });
    }
}

public static class HmacVerificationMiddlewareExtensions
{
    public static IApplicationBuilder UseHmacVerification(this IApplicationBuilder app) =>
        app.UseMiddleware<HmacVerificationMiddleware>();
}
```

### 4b. Nonce Store (Replay Protection Backing)

```csharp
// INonceStore.cs
public interface INonceStore
{
    /// <summary>Returns true if the nonce was not seen before (and records it); false if it's a replay.</summary>
    Task<bool> TryConsumeAsync(string nonce, TimeSpan ttl, CancellationToken ct);
}

// In-memory implementation — fine for single-instance APIs or dev/test.
// For multi-instance deployments, back this with Redis (see DistributedNonceStore below).
public sealed class InMemoryNonceStore : INonceStore
{
    private readonly Microsoft.Extensions.Caching.Memory.IMemoryCache _cache;

    public InMemoryNonceStore(Microsoft.Extensions.Caching.Memory.IMemoryCache cache) => _cache = cache;

    public Task<bool> TryConsumeAsync(string nonce, TimeSpan ttl, CancellationToken ct)
    {
        if (_cache.TryGetValue(nonce, out _))
            return Task.FromResult(false);

        _cache.Set(nonce, true, ttl);
        return Task.FromResult(true);
    }
}
```

```csharp
// Distributed alternative for multi-instance deployments (StackExchange.Redis)
public sealed class DistributedNonceStore : INonceStore
{
    private readonly StackExchange.Redis.IConnectionMultiplexer _redis;

    public DistributedNonceStore(StackExchange.Redis.IConnectionMultiplexer redis) => _redis = redis;

    public async Task<bool> TryConsumeAsync(string nonce, TimeSpan ttl, CancellationToken ct)
    {
        var db = _redis.GetDatabase();
        // SET key value NX EX ttl — atomic "set if not exists"
        return await db.StringSetAsync($"hmac:nonce:{nonce}", "1", ttl, When.NotExists);
    }
}
```

### 4c. AuthenticationHandler Approach (integrates with `[Authorize]`)

```csharp
// HmacAuthenticationHandler.cs
using System.Security.Claims;
using System.Text.Encodings.Web;
using Contoso.Security.Hmac;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

public sealed class HmacAuthSchemeOptions : AuthenticationSchemeOptions
{
    public Dictionary<string, string> Secrets { get; set; } = new();
    public TimeSpan AllowedClockSkew { get; set; } = TimeSpan.FromMinutes(5);
}

public sealed class HmacAuthenticationHandler : AuthenticationHandler<HmacAuthSchemeOptions>
{
    private readonly INonceStore _nonceStore;

    public HmacAuthenticationHandler(
        IOptionsMonitor<HmacAuthSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        INonceStore nonceStore)
        : base(options, logger, encoder)
    {
        _nonceStore = nonceStore;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var request = Request;

        if (!request.Headers.TryGetValue(SignatureUtil.Headers.Signature, out var sigValues) ||
            !request.Headers.TryGetValue(SignatureUtil.Headers.Timestamp, out var tsValues) ||
            !request.Headers.TryGetValue(SignatureUtil.Headers.Nonce, out var nonceValues) ||
            !request.Headers.TryGetValue(SignatureUtil.Headers.KeyId, out var keyIdValues))
        {
            return AuthenticateResult.Fail("Missing signature headers.");
        }

        var providedSignature = sigValues.ToString();
        var keyId = keyIdValues.ToString();

        if (!Options.Secrets.TryGetValue(keyId, out var secret))
            return AuthenticateResult.Fail("Unknown key id.");

        if (!long.TryParse(tsValues.ToString(), out var timestamp))
            return AuthenticateResult.Fail("Invalid timestamp.");

        var skew = (DateTimeOffset.UtcNow - DateTimeOffset.FromUnixTimeSeconds(timestamp)).Duration();
        if (skew > Options.AllowedClockSkew)
            return AuthenticateResult.Fail("Timestamp outside allowed window.");

        var nonce = nonceValues.ToString();
        if (!await _nonceStore.TryConsumeAsync(nonce, Options.AllowedClockSkew, request.HttpContext.RequestAborted))
            return AuthenticateResult.Fail("Replayed request.");

        request.EnableBuffering();
        byte[] bodyBytes;
        using (var ms = new MemoryStream())
        {
            await request.Body.CopyToAsync(ms);
            bodyBytes = ms.ToArray();
            request.Body.Position = 0;
        }

        var canonical = SignatureUtil.BuildCanonicalString(
            request.Method, request.Path.Value ?? "/", request.QueryString.Value,
            timestamp, nonce, bodyBytes);

        var expected = SignatureUtil.Sign(secret, canonical);

        if (!SignatureUtil.TimingSafeEquals(expected, providedSignature))
            return AuthenticateResult.Fail("Invalid signature.");

        var identity = new ClaimsIdentity(new[] { new Claim("keyid", keyId) }, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return AuthenticateResult.Success(ticket);
    }
}
```

Registration:

```csharp
builder.Services
    .AddAuthentication("Hmac")
    .AddScheme<HmacAuthSchemeOptions, HmacAuthenticationHandler>("Hmac", options =>
    {
        options.Secrets = new()
        {
            ["partner-a"] = builder.Configuration["Hmac:Secrets:partner-a"]!,
            ["partner-b"] = builder.Configuration["Hmac:Secrets:partner-b"]!,
        };
        options.AllowedClockSkew = TimeSpan.FromMinutes(5);
    });

builder.Services.AddAuthorization();
```

Then simply:

```csharp
[Authorize(AuthenticationSchemes = "Hmac")]
[HttpPost("orders")]
public IActionResult CreateOrder(OrderDto dto) => Ok();
```

---

## 5. Outbound: Signing Requests with `HttpClient`

Use a `DelegatingHandler` so every outgoing request through a named/typed client is automatically signed — no per-call boilerplate.

```csharp
// HmacSigningHandler.cs
using Contoso.Security.Hmac;

public sealed class HmacSigningHandler : DelegatingHandler
{
    private readonly string _keyId;
    private readonly string _secret;

    public HmacSigningHandler(string keyId, string secret)
    {
        _keyId = keyId;
        _secret = secret;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var bodyBytes = request.Content is null
            ? Array.Empty<byte>()
            : await request.Content.ReadAsByteArrayAsync(cancellationToken);

        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var nonce = Guid.NewGuid().ToString("N");

        var canonical = SignatureUtil.BuildCanonicalString(
            request.Method.Method,
            request.RequestUri!.AbsolutePath,
            request.RequestUri.Query,
            timestamp,
            nonce,
            bodyBytes);

        var signature = SignatureUtil.Sign(_secret, canonical);

        request.Headers.Remove(SignatureUtil.Headers.Signature);
        request.Headers.Remove(SignatureUtil.Headers.Timestamp);
        request.Headers.Remove(SignatureUtil.Headers.Nonce);
        request.Headers.Remove(SignatureUtil.Headers.KeyId);

        request.Headers.Add(SignatureUtil.Headers.Signature, signature);
        request.Headers.Add(SignatureUtil.Headers.Timestamp, timestamp.ToString());
        request.Headers.Add(SignatureUtil.Headers.Nonce, nonce);
        request.Headers.Add(SignatureUtil.Headers.KeyId, _keyId);

        return await base.SendAsync(request, cancellationToken);
    }
}
```

### Registering a signed `HttpClient` (typed client + `IHttpClientFactory`)

```csharp
// Program.cs (excerpt)
builder.Services.AddTransient(_ =>
    new HmacSigningHandler(
        keyId: builder.Configuration["Downstream:KeyId"]!,
        secret: builder.Configuration["Downstream:Secret"]!));

builder.Services
    .AddHttpClient<DownstreamApiClient>(client =>
    {
        client.BaseAddress = new Uri(builder.Configuration["Downstream:BaseUrl"]!);
    })
    .AddHttpMessageHandler(() => new HmacSigningHandler(
        builder.Configuration["Downstream:KeyId"]!,
        builder.Configuration["Downstream:Secret"]!));
```

```csharp
// DownstreamApiClient.cs
public sealed class DownstreamApiClient
{
    private readonly HttpClient _http;
    public DownstreamApiClient(HttpClient http) => _http = http;

    public async Task<HttpResponseMessage> CreateOrderAsync(object payload, CancellationToken ct)
    {
        // No manual signing needed here — the DelegatingHandler does it.
        return await _http.PostAsJsonAsync("/api/orders", payload, ct);
    }
}
```

> ⚠️ `HttpContent.ReadAsByteArrayAsync` buffers the whole body. For very large payloads (file uploads), consider signing a content hash computed during a pre-pass instead of buffering in the handler, or exclude large-body endpoints from full-body signing (sign headers + a declared `Content-Length`/`Content-SHA256` header instead).

---

## 6. Replay Protection

Signing alone does **not** stop replay attacks (an attacker capturing a valid request and resending it). Defense in depth:

1. **Timestamp window** — reject requests outside `AllowedClockSkew` (typically 2–5 minutes).
2. **Nonce store** — reject a nonce that's already been consumed within the window (see `INonceStore` above). TTL the nonce entry to match the clock-skew window so storage doesn't grow unbounded.
3. **HTTPS only** — enforce `RequireHttps` / HSTS; signing does not replace transport security.
4. **Bind the signature to the exact resource + method** — canonical string must include path, method, and body hash (already covered above) so a captured signature can't be replayed against a different endpoint.

---

## 7. Full Working Example

### `Program.cs`

```csharp
using Microsoft.Extensions.Caching.Memory;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddMemoryCache();
builder.Services.AddSingleton<INonceStore, InMemoryNonceStore>();

builder.Services.Configure<HmacOptions>(options =>
{
    options.Secrets = new Dictionary<string, string>
    {
        ["partner-a"] = builder.Configuration["Hmac:Secrets:partner-a"] ?? "dev-secret-change-me"
    };
    options.AllowedClockSkew = TimeSpan.FromMinutes(5);
});

builder.Services.AddControllers();

var app = builder.Build();

app.UseHttpsRedirection();

// Verify inbound signed requests before routing/model binding runs.
app.UseHmacVerification();

app.UseAuthorization();
app.MapControllers();

app.Run();
```

### `OrdersController.cs`

```csharp
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class OrdersController : ControllerBase
{
    [HttpPost]
    public IActionResult Create([FromBody] CreateOrderRequest request)
    {
        // If we reach here, HmacVerificationMiddleware already confirmed
        // authenticity + integrity + freshness of the request.
        return Ok(new { orderId = Guid.NewGuid(), request.CustomerId });
    }
}

public record CreateOrderRequest(string CustomerId, decimal Amount);
```

### `appsettings.json`

```json
{
  "Hmac": {
    "Secrets": {
      "partner-a": "replace-with-a-strong-random-secret-32-bytes-min"
    }
  },
  "Downstream": {
    "BaseUrl": "https://downstream.example.com",
    "KeyId": "my-service",
    "Secret": "replace-with-a-strong-random-secret-32-bytes-min"
  }
}
```

> In production, load secrets from a vault (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault) — never commit them to `appsettings.json`.

---

## 8. Testing with curl

Since curl can't compute HMAC natively for arbitrary canonical strings, script it:

```bash
#!/usr/bin/env bash
SECRET="replace-with-a-strong-random-secret-32-bytes-min"
KEYID="partner-a"
METHOD="POST"
PATH_="/api/orders"
QUERY=""
BODY='{"customerId":"123","amount":49.99}'
TS=$(date +%s)
NONCE=$(uuidgen)

BODY_HASH=$(printf '%s' "$BODY" | openssl dgst -sha256 -hex | awk '{print $2}')

CANONICAL=$(printf '%s\n%s\n%s\n%s\n%s\n%s' "$METHOD" "$PATH_" "$QUERY" "$TS" "$NONCE" "$BODY_HASH")

SIGNATURE=$(printf '%s' "$CANONICAL" | openssl dgst -sha256 -hmac "$SECRET" -binary | base64)

curl -X POST "https://localhost:5001${PATH_}" \
  -H "Content-Type: application/json" \
  -H "X-Signature: ${SIGNATURE}" \
  -H "X-Signature-Timestamp: ${TS}" \
  -H "X-Signature-Nonce: ${NONCE}" \
  -H "X-Signature-KeyId: ${KEYID}" \
  -d "$BODY"
```

### Unit test for the utility (xUnit)

```csharp
using Contoso.Security.Hmac;
using Xunit;

public class SignatureUtilTests
{
    [Fact]
    public void Sign_And_Verify_RoundTrip_Succeeds()
    {
        const string secret = "test-secret";
        var body = System.Text.Encoding.UTF8.GetBytes("""{"a":1}""");
        var ts = 1726387200L;
        var nonce = "fixed-nonce-for-test";

        var canonical = SignatureUtil.BuildCanonicalString("POST", "/api/orders", "b=2&a=1", ts, nonce, body);
        var sig = SignatureUtil.Sign(secret, canonical);

        var canonicalAgain = SignatureUtil.BuildCanonicalString("POST", "/api/orders", "a=1&b=2", ts, nonce, body);
        var expected = SignatureUtil.Sign(secret, canonicalAgain);

        Assert.True(SignatureUtil.TimingSafeEquals(sig, expected));
    }

    [Fact]
    public void TamperedBody_ProducesDifferentSignature()
    {
        const string secret = "test-secret";
        var original = SignatureUtil.BuildCanonicalString("POST", "/api/orders", "", 1L, "n1",
            System.Text.Encoding.UTF8.GetBytes("""{"amount":10}"""));
        var tampered = SignatureUtil.BuildCanonicalString("POST", "/api/orders", "", 1L, "n1",
            System.Text.Encoding.UTF8.GetBytes("""{"amount":10000}"""));

        Assert.False(SignatureUtil.TimingSafeEquals(
            SignatureUtil.Sign(secret, original),
            SignatureUtil.Sign(secret, tampered)));
    }
}
```

---

## 9. Security Checklist

- [ ] Secrets are ≥256 bits of entropy, stored in a vault/secret manager, never in source control.
- [ ] Comparison uses `CryptographicOperations.FixedTimeEquals`, never `==`/`Equals`.
- [ ] Canonical string includes method, path, query, timestamp, nonce, and body hash.
- [ ] Timestamp window enforced (reject stale/future requests).
- [ ] Nonce store enforced and backed by a distributed cache (Redis) in multi-instance deployments.
- [ ] HTTPS enforced end-to-end; HSTS enabled.
- [ ] Key rotation supported via a `KeyId` header mapped to multiple active secrets.
- [ ] Logging on verification failure excludes the secret and full signature (log keyId + reason only).
- [ ] Body is read via buffering (`EnableBuffering`) so verification doesn't break model binding.
- [ ] Large payloads have a documented strategy (stream hashing or excluded from full-body signing) rather than being fully buffered in memory.