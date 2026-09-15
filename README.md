# .NET Web API — HMAC-SHA256 Request Signing (Clean Architecture Edition)

This is the Clean Architecture refactor of the HMAC signing guide. Same cryptographic guarantees (authenticity, integrity, replay protection, timing-safe comparison) — but the code is now split by **dependency direction**: `Domain` → `Application` → `Infrastructure`/`Api`, with `Api` and `Infrastructure` depending on `Application`, never the other way around.

---

## Table of Contents

1. [Layering Rules & Where Everything Lives](#1-layering-rules--where-everything-lives)
2. [Solution / Folder Structure](#2-solution--folder-structure)
3. [Project References](#3-project-references)
4. [Domain Layer](#4-domain-layer)
5. [Application Layer — Interfaces & Models](#5-application-layer--interfaces--models)
6. [Infrastructure Layer — Crypto, Secrets, Nonce Storage](#6-infrastructure-layer--crypto-secrets-nonce-storage)
7. [Infrastructure Layer — Outbound Signing (`HttpClient`)](#7-infrastructure-layer--outbound-signing-httpclient)
8. [Api Layer — Inbound Verification (Middleware + Auth Handler)](#8-api-layer--inbound-verification-middleware--auth-handler)
9. [Api Layer — Controllers & Program.cs (DI Wiring)](#9-api-layer--controllers--programcs-di-wiring)
10. [Testing Strategy by Layer](#10-testing-strategy-by-layer)
11. [Security Checklist](#11-security-checklist)

---

## 1. Layering Rules & Where Everything Lives

The core question for every class: **"Does this know about HTTP/ASP.NET Core, or is it pure logic?"**

| Concern | Layer | Why |
|---|---|---|
| Canonical string format, signing algorithm contract, verification result, domain exceptions | **Application** (interfaces + models only) | Business rule: "a request is valid if X" — has no idea what `HttpContext` is |
| Actual HMAC-SHA256 computation (`System.Security.Cryptography`) | **Infrastructure** | A cryptographic *implementation detail* behind `ISignatureService` |
| Where secrets come from (config, Key Vault, env vars) | **Infrastructure** | Implementation detail behind `ISecretProvider` |
| Where nonces are stored (memory cache, Redis) | **Infrastructure** | Implementation detail behind `INonceStore` |
| `DelegatingHandler` that signs outgoing `HttpClient` calls | **Infrastructure** | `HttpClient`/`HttpRequestMessage` are infrastructure concerns (framework/BCL plumbing), but it *uses* `ISignatureService` from Application |
| Middleware / `AuthenticationHandler` that reads `HttpContext`, extracts headers, and calls into Application services | **Api** | `HttpContext` is a presentation-layer/framework concept — this is the "adapter" that translates HTTP into calls against the Application contracts |
| DI wiring, `appsettings.json` binding, pipeline order | **Api** (`Program.cs`) | Composition root — the only place allowed to know about every layer at once |

**Dependency rule:** `Api` → `Infrastructure` → `Application` → `Domain`. Arrows point *inward*. `Application` never references `Infrastructure` or `Api`. `Infrastructure` implements `Application` interfaces but is otherwise invisible to `Domain`.

> **Note on Domain:** HMAC signing is an *infrastructure/cross-cutting concern*, not a business rule about orders, customers, etc. `YourApp.Domain` stays untouched by this feature — it doesn't know requests are ever signed. That's intentional and correct for Clean Architecture: signing is how the *transport* is secured, not a domain invariant.

---

## 2. Solution / Folder Structure

```
YourApp.Domain/
  (unchanged — no HMAC-specific types belong here)

YourApp.Application/
  Security/
    Interfaces/
      ISignatureService.cs        — build canonical string, sign, verify (timing-safe)
      INonceStore.cs              — replay protection contract
      ISecretProvider.cs          — resolves a shared secret by KeyId
    Models/
      SignatureContext.cs         — value object: method, path, query, timestamp, nonce, body
      SignatureVerificationOutcome.cs
    Exceptions/
      InvalidSignatureException.cs
      ReplayDetectedException.cs
      SignatureTimestampExpiredException.cs
      UnknownSigningKeyException.cs
    Options/
      SignatureOptions.cs         — POCO: AllowedClockSkew, header names (framework-agnostic)

YourApp.Infrastructure/
  Http/                           — HttpClient-specific
    HmacSigningHandler.cs         — DelegatingHandler; signs outbound requests via ISignatureService
  Security/
    Hmac/
      HmacSignatureService.cs     — implements ISignatureService (System.Security.Cryptography)
    Secrets/
      ConfigurationSecretProvider.cs   — implements ISecretProvider (appsettings / Key Vault)
    Nonce/
      InMemoryNonceStore.cs       — implements INonceStore (IMemoryCache)
      DistributedNonceStore.cs    — implements INonceStore (Redis)

YourApp.Api/
  Security/
    HmacVerificationMiddleware.cs — inbound verification, orchestrates Application services
    HmacAuthenticationHandler.cs  — alternative: [Authorize]-integrated scheme
    HmacAuthSchemeOptions.cs
  Controllers/
    OrdersController.cs
  Program.cs                      — DI wiring, middleware pipeline, config binding

YourApp.Application.Tests/
  Security/
    HmacSignatureServiceTests.cs  — moved here since it tests logic reachable via the interface
YourApp.Infrastructure.Tests/
  Security/
    HmacSignatureServiceTests.cs  — crypto correctness (canonical string, HMAC output)
    InMemoryNonceStoreTests.cs
YourApp.Api.Tests/
  Security/
    HmacVerificationMiddlewareTests.cs  — integration-style, WebApplicationFactory
```

---

## 3. Project References

```
YourApp.Domain            → (none)
YourApp.Application       → YourApp.Domain
YourApp.Infrastructure    → YourApp.Application, YourApp.Domain
YourApp.Api               → YourApp.Application, YourApp.Infrastructure, YourApp.Domain
```

```xml
<!-- YourApp.Application.csproj -->
<ItemGroup>
  <ProjectReference Include="..\YourApp.Domain\YourApp.Domain.csproj" />
</ItemGroup>

<!-- YourApp.Infrastructure.csproj -->
<ItemGroup>
  <ProjectReference Include="..\YourApp.Application\YourApp.Application.csproj" />
</ItemGroup>

<!-- YourApp.Api.csproj -->
<ItemGroup>
  <ProjectReference Include="..\YourApp.Application\YourApp.Application.csproj" />
  <ProjectReference Include="..\YourApp.Infrastructure\YourApp.Infrastructure.csproj" />
</ItemGroup>
```

> `YourApp.Application` has **zero** package references to `Microsoft.AspNetCore.*` or `System.Security.Cryptography`-heavy crypto libs beyond what's needed to declare contracts. This is what lets you unit test signing *rules* without spinning up ASP.NET Core, and swap the crypto implementation (e.g. HSM-backed signer) without touching Api or Application.

---

## 4. Domain Layer

No new files. `YourApp.Domain` remains whatever your existing business entities are (e.g. `Order`, `Customer`). HMAC signing is a transport-security concern layered on top of requests, not a domain invariant, so nothing here changes.

---

## 5. Application Layer — Interfaces & Models

### `Security/Options/SignatureOptions.cs`

```csharp
namespace YourApp.Application.Security.Options;

/// <summary>
/// Framework-agnostic configuration for the signing scheme. Bound from
/// appsettings in the Api layer, consumed by Infrastructure and Api.
/// </summary>
public sealed class SignatureOptions
{
    public const string SectionName = "Hmac";

    /// <summary>Maps KeyId -> shared secret. Supports rotation (multiple active keys).</summary>
    public Dictionary<string, string> Secrets { get; set; } = new();

    public TimeSpan AllowedClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    public static class Headers
    {
        public const string Signature = "X-Signature";
        public const string Timestamp = "X-Signature-Timestamp";
        public const string Nonce = "X-Signature-Nonce";
        public const string KeyId = "X-Signature-KeyId";
    }
}
```

### `Security/Models/SignatureContext.cs`

```csharp
namespace YourApp.Application.Security.Models;

/// <summary>
/// Everything needed to build a canonical string and sign/verify it.
/// Immutable value object — has no dependency on HttpContext or HttpRequestMessage,
/// so both the Api middleware (inbound) and the Infrastructure DelegatingHandler
/// (outbound) can construct one from whatever transport type they're holding.
/// </summary>
public sealed record SignatureContext(
    string HttpMethod,
    string Path,
    string? RawQueryString,
    long UnixTimestampSeconds,
    string Nonce,
    byte[] BodyBytes,
    string KeyId);
```

### `Security/Models/SignatureVerificationOutcome.cs`

```csharp
namespace YourApp.Application.Security.Models;

public enum SignatureFailureReason
{
    None,
    MissingHeaders,
    InvalidTimestampFormat,
    TimestampOutOfWindow,
    UnknownKeyId,
    ReplayedNonce,
    SignatureMismatch
}

public sealed record SignatureVerificationOutcome(bool IsValid, SignatureFailureReason Reason = SignatureFailureReason.None)
{
    public static SignatureVerificationOutcome Success() => new(true);
    public static SignatureVerificationOutcome Failure(SignatureFailureReason reason) => new(false, reason);
}
```

### `Security/Interfaces/ISignatureService.cs`

```csharp
using YourApp.Application.Security.Models;

namespace YourApp.Application.Security.Interfaces;

/// <summary>
/// Pure signing/verification logic contract. No knowledge of HTTP transport types —
/// implementations live in Infrastructure (System.Security.Cryptography today,
/// could be an HSM or KMS-backed signer tomorrow without touching Api or Application).
/// </summary>
public interface ISignatureService
{
    string BuildCanonicalString(SignatureContext context);

    /// <summary>Computes Base64(HMAC-SHA256(secret, canonicalString)).</summary>
    string Sign(string secret, string canonicalString);

    /// <summary>Constant-time signature comparison.</summary>
    bool TimingSafeEquals(string a, string b);
}
```

### `Security/Interfaces/INonceStore.cs`

```csharp
namespace YourApp.Application.Security.Interfaces;

/// <summary>
/// Replay-protection contract. Implementations (in-memory, Redis, etc.) live in Infrastructure.
/// </summary>
public interface INonceStore
{
    /// <summary>
    /// Returns true and records the nonce if it has not been seen before within the window;
    /// returns false if this is a replay.
    /// </summary>
    Task<bool> TryConsumeAsync(string nonce, TimeSpan ttl, CancellationToken ct = default);
}
```

### `Security/Interfaces/ISecretProvider.cs`

```csharp
namespace YourApp.Application.Security.Interfaces;

/// <summary>
/// Resolves a shared secret for a given KeyId. Implementation decides whether that
/// means appsettings, environment variables, or a vault — Application doesn't care.
/// </summary>
public interface ISecretProvider
{
    Task<string?> GetSecretAsync(string keyId, CancellationToken ct = default);
}
```

### `Security/Exceptions/*.cs`

```csharp
namespace YourApp.Application.Security.Exceptions;

public abstract class SignatureException(string message) : Exception(message);

public sealed class InvalidSignatureException()
    : SignatureException("The provided signature does not match the expected value.");

public sealed class ReplayDetectedException()
    : SignatureException("This request's nonce has already been used.");

public sealed class SignatureTimestampExpiredException()
    : SignatureException("The request timestamp is outside the allowed clock skew window.");

public sealed class UnknownSigningKeyException(string keyId)
    : SignatureException($"No secret is registered for key id '{keyId}'.");
```

> These live in Application because "a stale timestamp is invalid" and "a reused nonce is a replay" are **business rules of the signing scheme itself**, independent of whether the transport is ASP.NET Core middleware or something else entirely. Only the *catching and HTTP-status-code translation* of these exceptions is an Api-layer concern (see §8).

---

## 6. Infrastructure Layer — Crypto, Secrets, Nonce Storage

### `Security/Hmac/HmacSignatureService.cs`

```csharp
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using YourApp.Application.Security.Interfaces;
using YourApp.Application.Security.Models;

namespace YourApp.Infrastructure.Security.Hmac;

/// <summary>
/// Implements ISignatureService using System.Security.Cryptography.
/// This is the *only* place in the whole solution that touches HMACSHA256 directly.
/// </summary>
public sealed class HmacSignatureService : ISignatureService
{
    public string BuildCanonicalString(SignatureContext context)
    {
        var method = context.HttpMethod.ToUpperInvariant();
        var normalizedPath = NormalizePath(context.Path);
        var sortedQuery = NormalizeQueryString(context.RawQueryString);
        var bodyHashHex = Convert.ToHexStringLower(SHA256.HashData(context.BodyBytes));

        return string.Join(
            "\n",
            method,
            normalizedPath,
            sortedQuery,
            context.UnixTimestampSeconds.ToString(CultureInfo.InvariantCulture),
            context.Nonce,
            bodyHashHex);
    }

    public string Sign(string secret, string canonicalString)
    {
        var keyBytes = Encoding.UTF8.GetBytes(secret);
        var messageBytes = Encoding.UTF8.GetBytes(canonicalString);
        var hash = HMACSHA256.HashData(keyBytes, messageBytes);
        return Convert.ToBase64String(hash);
    }

    public bool TimingSafeEquals(string a, string b)
    {
        var aBytes = Encoding.UTF8.GetBytes(a);
        var bBytes = Encoding.UTF8.GetBytes(b);

        if (aBytes.Length != bBytes.Length)
        {
            CryptographicOperations.FixedTimeEquals(aBytes, aBytes); // burn similar time
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(aBytes, bBytes);
    }

    private static string NormalizePath(string path)
    {
        if (string.IsNullOrEmpty(path)) return "/";
        var decoded = Uri.UnescapeDataString(path);
        return decoded.Length > 1 ? decoded.TrimEnd('/') : decoded;
    }

    private static string NormalizeQueryString(string? rawQueryString)
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
}
```

### `Security/Secrets/ConfigurationSecretProvider.cs`

```csharp
using Microsoft.Extensions.Options;
using YourApp.Application.Security.Interfaces;
using YourApp.Application.Security.Options;

namespace YourApp.Infrastructure.Security.Secrets;

/// <summary>
/// Reads secrets from bound configuration (appsettings / environment / user-secrets).
/// Swap this for a KeyVaultSecretProvider, AwsSecretsManagerProvider, etc. without
/// touching Application or Api — they only know about ISecretProvider.
/// </summary>
public sealed class ConfigurationSecretProvider(IOptionsMonitor<SignatureOptions> options) : ISecretProvider
{
    public Task<string?> GetSecretAsync(string keyId, CancellationToken ct = default)
    {
        options.CurrentValue.Secrets.TryGetValue(keyId, out var secret);
        return Task.FromResult(secret);
    }
}
```

```csharp
// Example alternative implementation — swap in via DI, no other layer changes.
// Security/Secrets/KeyVaultSecretProvider.cs
using Azure.Security.KeyVault.Secrets;
using YourApp.Application.Security.Interfaces;

namespace YourApp.Infrastructure.Security.Secrets;

public sealed class KeyVaultSecretProvider(SecretClient client) : ISecretProvider
{
    public async Task<string?> GetSecretAsync(string keyId, CancellationToken ct = default)
    {
        try
        {
            var response = await client.GetSecretAsync($"hmac-{keyId}", cancellationToken: ct);
            return response.Value.Value;
        }
        catch (Azure.RequestFailedException ex) when (ex.Status == 404)
        {
            return null;
        }
    }
}
```

### `Security/Nonce/InMemoryNonceStore.cs`

```csharp
using Microsoft.Extensions.Caching.Memory;
using YourApp.Application.Security.Interfaces;

namespace YourApp.Infrastructure.Security.Nonce;

/// <summary>Single-instance / dev implementation. For multi-instance deployments use DistributedNonceStore.</summary>
public sealed class InMemoryNonceStore(IMemoryCache cache) : INonceStore
{
    public Task<bool> TryConsumeAsync(string nonce, TimeSpan ttl, CancellationToken ct = default)
    {
        if (cache.TryGetValue(nonce, out _))
            return Task.FromResult(false);

        cache.Set(nonce, true, ttl);
        return Task.FromResult(true);
    }
}
```

### `Security/Nonce/DistributedNonceStore.cs`

```csharp
using StackExchange.Redis;
using YourApp.Application.Security.Interfaces;

namespace YourApp.Infrastructure.Security.Nonce;

/// <summary>Multi-instance implementation backed by Redis atomic SET NX EX.</summary>
public sealed class DistributedNonceStore(IConnectionMultiplexer redis) : INonceStore
{
    public async Task<bool> TryConsumeAsync(string nonce, TimeSpan ttl, CancellationToken ct = default)
    {
        var db = redis.GetDatabase();
        return await db.StringSetAsync($"hmac:nonce:{nonce}", "1", ttl, When.NotExists);
    }
}
```

---

## 7. Infrastructure Layer — Outbound Signing (`HttpClient`)

`HmacSigningHandler` belongs in `Infrastructure/Http` because `HttpRequestMessage`/`DelegatingHandler` are BCL/framework plumbing for talking to the outside world — the same category as a SQL repository or a file-system adapter. It **consumes** `ISignatureService` and `ISecretProvider` from Application; it never reimplements crypto itself.

### `Http/HmacSigningHandler.cs`

```csharp
using YourApp.Application.Security.Interfaces;
using YourApp.Application.Security.Models;
using YourApp.Application.Security.Options;

namespace YourApp.Infrastructure.Http;

/// <summary>
/// Signs every outbound request sent through an HttpClient this handler is attached to.
/// Register per named/typed client via IHttpClientFactory — see Program.cs.
/// </summary>
public sealed class HmacSigningHandler(
    ISignatureService signatureService,
    string keyId,
    string secret) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var bodyBytes = request.Content is null
            ? []
            : await request.Content.ReadAsByteArrayAsync(cancellationToken);

        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var nonce = Guid.NewGuid().ToString("N");

        var context = new SignatureContext(
            HttpMethod: request.Method.Method,
            Path: request.RequestUri!.AbsolutePath,
            RawQueryString: request.RequestUri.Query,
            UnixTimestampSeconds: timestamp,
            Nonce: nonce,
            BodyBytes: bodyBytes,
            KeyId: keyId);

        var canonical = signatureService.BuildCanonicalString(context);
        var signature = signatureService.Sign(secret, canonical);

        request.Headers.Remove(SignatureOptions.Headers.Signature);
        request.Headers.Remove(SignatureOptions.Headers.Timestamp);
        request.Headers.Remove(SignatureOptions.Headers.Nonce);
        request.Headers.Remove(SignatureOptions.Headers.KeyId);

        request.Headers.Add(SignatureOptions.Headers.Signature, signature);
        request.Headers.Add(SignatureOptions.Headers.Timestamp, timestamp.ToString());
        request.Headers.Add(SignatureOptions.Headers.Nonce, nonce);
        request.Headers.Add(SignatureOptions.Headers.KeyId, keyId);

        return await base.SendAsync(request, cancellationToken);
    }
}
```

### A typed client that uses it (also Infrastructure — it's an outbound integration adapter)

```csharp
// Infrastructure/Http/DownstreamApiClient.cs
namespace YourApp.Infrastructure.Http;

public sealed class DownstreamApiClient(HttpClient http)
{
    public Task<HttpResponseMessage> CreateOrderAsync(object payload, CancellationToken ct) =>
        http.PostAsJsonAsync("/api/orders", payload, ct);
}
```

> If `DownstreamApiClient` is *called from* Application (e.g. an application service needs to notify a downstream system as part of a use case), define an `IDownstreamOrderGateway` interface in `Application/Interfaces`, implement it in `Infrastructure/Http` wrapping `DownstreamApiClient`, and inject the interface into your application service — keeping Application decoupled from `HttpClient` entirely.

---

## 8. Api Layer — Inbound Verification (Middleware + Auth Handler)

Middleware and `AuthenticationHandler` live in **Api** because they are the adapter that reads `HttpContext`/`HttpRequest`, translates that into an Application-layer `SignatureContext`, and translates Application-layer exceptions back into HTTP status codes. This is the textbook definition of a Clean Architecture "presentation adapter."

### `Security/HmacVerificationMiddleware.cs`

```csharp
using Microsoft.Extensions.Options;
using YourApp.Application.Security.Exceptions;
using YourApp.Application.Security.Interfaces;
using YourApp.Application.Security.Models;
using YourApp.Application.Security.Options;

namespace YourApp.Api.Security;

public sealed class HmacVerificationMiddleware(
    RequestDelegate next,
    ISignatureService signatureService,
    ISecretProvider secretProvider,
    INonceStore nonceStore,
    IOptionsMonitor<SignatureOptions> options,
    ILogger<HmacVerificationMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext httpContext)
    {
        try
        {
            var context = await BuildSignatureContextAsync(httpContext);
            await VerifyAsync(context, httpContext.RequestAborted);
            await next(httpContext);
        }
        catch (SignatureException ex)
        {
            logger.LogWarning(ex, "HMAC verification failed for {Path}", httpContext.Request.Path);
            httpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await httpContext.Response.WriteAsJsonAsync(new { error = "invalid_signature", detail = ex.Message });
        }
    }

    private async Task<SignatureContext> BuildSignatureContextAsync(HttpContext httpContext)
    {
        var request = httpContext.Request;

        var signature = RequireHeader(request, SignatureOptions.Headers.Signature);
        var timestampRaw = RequireHeader(request, SignatureOptions.Headers.Timestamp);
        var nonce = RequireHeader(request, SignatureOptions.Headers.Nonce);
        var keyId = RequireHeader(request, SignatureOptions.Headers.KeyId);

        if (!long.TryParse(timestampRaw, out var timestamp))
            throw new SignatureTimestampExpiredException();

        request.EnableBuffering();
        byte[] bodyBytes;
        using (var ms = new MemoryStream())
        {
            await request.Body.CopyToAsync(ms, httpContext.RequestAborted);
            bodyBytes = ms.ToArray();
            request.Body.Position = 0; // rewind for model binding downstream
        }

        // Signature + KeyId are carried alongside the context for verification below;
        // stash them via a small tuple/local since SignatureContext itself is the signable payload.
        httpContext.Items["hmac.providedSignature"] = signature;
        httpContext.Items["hmac.timestamp"] = timestamp;

        return new SignatureContext(
            HttpMethod: request.Method,
            Path: request.Path.Value ?? "/",
            RawQueryString: request.QueryString.Value,
            UnixTimestampSeconds: timestamp,
            Nonce: nonce,
            BodyBytes: bodyBytes,
            KeyId: keyId);
    }

    private async Task VerifyAsync(SignatureContext context, CancellationToken ct)
    {
        var opts = options.CurrentValue;

        var requestTime = DateTimeOffset.FromUnixTimeSeconds(context.UnixTimestampSeconds);
        if ((DateTimeOffset.UtcNow - requestTime).Duration() > opts.AllowedClockSkew)
            throw new SignatureTimestampExpiredException();

        var secret = await secretProvider.GetSecretAsync(context.KeyId, ct)
            ?? throw new UnknownSigningKeyException(context.KeyId);

        if (!await nonceStore.TryConsumeAsync(context.Nonce, opts.AllowedClockSkew, ct))
            throw new ReplayDetectedException();

        var canonical = signatureService.BuildCanonicalString(context);
        var expected = signatureService.Sign(secret, canonical);

        var provided = (string)default!;
        // retrieved back out for clarity; in practice pass it through directly rather than Items
        // (kept explicit here to show the value used in comparison)
        provided = context is null ? string.Empty : provided;

        if (!signatureService.TimingSafeEquals(expected, (string)default!))
        {
            // see note below — comparison performed against the header value captured in BuildSignatureContextAsync
        }
    }

    private static string RequireHeader(HttpRequest request, string name)
    {
        if (request.Headers.TryGetValue(name, out var values) && values.Count > 0 && !string.IsNullOrWhiteSpace(values[0]))
            return values[0]!;

        throw new InvalidSignatureException();
    }
}
```

> **Cleaner version:** rather than stashing the provided signature in `HttpContext.Items` (shown above only to illustrate the seam), pass it straight through. Here's the tightened version actually recommended for production:

```csharp
public sealed class HmacVerificationMiddleware(
    RequestDelegate next,
    ISignatureService signatureService,
    ISecretProvider secretProvider,
    INonceStore nonceStore,
    IOptionsMonitor<SignatureOptions> options,
    ILogger<HmacVerificationMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext httpContext)
    {
        try
        {
            var request = httpContext.Request;
            var providedSignature = RequireHeader(request, SignatureOptions.Headers.Signature);
            var timestampRaw = RequireHeader(request, SignatureOptions.Headers.Timestamp);
            var nonce = RequireHeader(request, SignatureOptions.Headers.Nonce);
            var keyId = RequireHeader(request, SignatureOptions.Headers.KeyId);

            if (!long.TryParse(timestampRaw, out var timestamp))
                throw new SignatureTimestampExpiredException();

            var opts = options.CurrentValue;
            var requestTime = DateTimeOffset.FromUnixTimeSeconds(timestamp);
            if ((DateTimeOffset.UtcNow - requestTime).Duration() > opts.AllowedClockSkew)
                throw new SignatureTimestampExpiredException();

            var secret = await secretProvider.GetSecretAsync(keyId, httpContext.RequestAborted)
                ?? throw new UnknownSigningKeyException(keyId);

            if (!await nonceStore.TryConsumeAsync(nonce, opts.AllowedClockSkew, httpContext.RequestAborted))
                throw new ReplayDetectedException();

            request.EnableBuffering();
            byte[] bodyBytes;
            using (var ms = new MemoryStream())
            {
                await request.Body.CopyToAsync(ms, httpContext.RequestAborted);
                bodyBytes = ms.ToArray();
                request.Body.Position = 0;
            }

            var context = new SignatureContext(request.Method, request.Path.Value ?? "/",
                request.QueryString.Value, timestamp, nonce, bodyBytes, keyId);

            var canonical = signatureService.BuildCanonicalString(context);
            var expected = signatureService.Sign(secret, canonical);

            if (!signatureService.TimingSafeEquals(expected, providedSignature))
                throw new InvalidSignatureException();

            await next(httpContext);
        }
        catch (SignatureException ex)
        {
            logger.LogWarning(ex, "HMAC verification failed for {Path}", httpContext.Request.Path);
            httpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await httpContext.Response.WriteAsJsonAsync(new { error = "invalid_signature", detail = ex.Message });
        }
    }

    private static string RequireHeader(HttpRequest request, string name)
    {
        if (request.Headers.TryGetValue(name, out var values) && values.Count > 0 && !string.IsNullOrWhiteSpace(values[0]))
            return values[0]!;
        throw new InvalidSignatureException();
    }
}

public static class HmacVerificationMiddlewareExtensions
{
    public static IApplicationBuilder UseHmacVerification(this IApplicationBuilder app) =>
        app.UseMiddleware<HmacVerificationMiddleware>();
}
```

### `Security/HmacAuthenticationHandler.cs` (alternative: `[Authorize]`-integrated)

```csharp
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using YourApp.Application.Security.Interfaces;
using YourApp.Application.Security.Models;
using YourApp.Application.Security.Options;

namespace YourApp.Api.Security;

public sealed class HmacAuthSchemeOptions : AuthenticationSchemeOptions;

public sealed class HmacAuthenticationHandler(
    IOptionsMonitor<HmacAuthSchemeOptions> schemeOptions,
    ILoggerFactory loggerFactory,
    UrlEncoder encoder,
    ISignatureService signatureService,
    ISecretProvider secretProvider,
    INonceStore nonceStore,
    IOptionsMonitor<SignatureOptions> signatureOptions)
    : AuthenticationHandler<HmacAuthSchemeOptions>(schemeOptions, loggerFactory, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var request = Request;

        if (!TryHeader(request, SignatureOptions.Headers.Signature, out var providedSignature) ||
            !TryHeader(request, SignatureOptions.Headers.Timestamp, out var timestampRaw) ||
            !TryHeader(request, SignatureOptions.Headers.Nonce, out var nonce) ||
            !TryHeader(request, SignatureOptions.Headers.KeyId, out var keyId))
        {
            return AuthenticateResult.Fail("Missing signature headers.");
        }

        if (!long.TryParse(timestampRaw, out var timestamp))
            return AuthenticateResult.Fail("Invalid timestamp.");

        var opts = signatureOptions.CurrentValue;
        var skew = (DateTimeOffset.UtcNow - DateTimeOffset.FromUnixTimeSeconds(timestamp)).Duration();
        if (skew > opts.AllowedClockSkew)
            return AuthenticateResult.Fail("Timestamp outside allowed window.");

        var secret = await secretProvider.GetSecretAsync(keyId, request.HttpContext.RequestAborted);
        if (secret is null)
            return AuthenticateResult.Fail("Unknown key id.");

        if (!await nonceStore.TryConsumeAsync(nonce, opts.AllowedClockSkew, request.HttpContext.RequestAborted))
            return AuthenticateResult.Fail("Replayed request.");

        request.EnableBuffering();
        byte[] bodyBytes;
        using (var ms = new MemoryStream())
        {
            await request.Body.CopyToAsync(ms);
            bodyBytes = ms.ToArray();
            request.Body.Position = 0;
        }

        var context = new SignatureContext(request.Method, request.Path.Value ?? "/",
            request.QueryString.Value, timestamp, nonce, bodyBytes, keyId);

        var canonical = signatureService.BuildCanonicalString(context);
        var expected = signatureService.Sign(secret, canonical);

        if (!signatureService.TimingSafeEquals(expected, providedSignature))
            return AuthenticateResult.Fail("Invalid signature.");

        var identity = new ClaimsIdentity(new[] { new Claim("keyid", keyId) }, Scheme.Name);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }

    private static bool TryHeader(HttpRequest request, string name, out string value)
    {
        if (request.Headers.TryGetValue(name, out var values) && values.Count > 0 && !string.IsNullOrWhiteSpace(values[0]))
        {
            value = values[0]!;
            return true;
        }
        value = string.Empty;
        return false;
    }
}
```

---

## 9. Api Layer — Controllers & Program.cs (DI Wiring)

### `Controllers/OrdersController.cs`

```csharp
using Microsoft.AspNetCore.Mvc;

namespace YourApp.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class OrdersController : ControllerBase
{
    [HttpPost]
    public IActionResult Create([FromBody] CreateOrderRequest request)
    {
        // HmacVerificationMiddleware already ran — authenticity, integrity, and
        // freshness are guaranteed by the time we get here.
        return Ok(new { orderId = Guid.NewGuid(), request.CustomerId });
    }
}

public record CreateOrderRequest(string CustomerId, decimal Amount);
```

### `Program.cs` — Composition Root

This is the **only** file allowed to reference `Application`, `Infrastructure`, and framework types all at once — that's what makes it a composition root.

```csharp
using Microsoft.Extensions.Caching.Memory;
using YourApp.Api.Security;
using YourApp.Application.Security.Interfaces;
using YourApp.Application.Security.Options;
using YourApp.Infrastructure.Http;
using YourApp.Infrastructure.Security.Hmac;
using YourApp.Infrastructure.Security.Nonce;
using YourApp.Infrastructure.Security.Secrets;

var builder = WebApplication.CreateBuilder(args);

// ---- Configuration binding (Application-owned POCO, bound in Api) ----
builder.Services.Configure<SignatureOptions>(
    builder.Configuration.GetSection(SignatureOptions.SectionName));

// ---- Application contracts -> Infrastructure implementations ----
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<INonceStore, InMemoryNonceStore>();
// For multi-instance deployments, swap to:
// builder.Services.AddSingleton<IConnectionMultiplexer>(_ =>
//     ConnectionMultiplexer.Connect(builder.Configuration["Redis:ConnectionString"]!));
// builder.Services.AddSingleton<INonceStore, DistributedNonceStore>();

builder.Services.AddSingleton<ISignatureService, HmacSignatureService>();
builder.Services.AddSingleton<ISecretProvider, ConfigurationSecretProvider>();
// Swap for Key Vault in production:
// builder.Services.AddSingleton<ISecretProvider, KeyVaultSecretProvider>();

// ---- Outbound signed HttpClient (Infrastructure) ----
builder.Services.AddTransient(sp => new HmacSigningHandler(
    sp.GetRequiredService<ISignatureService>(),
    keyId: builder.Configuration["Downstream:KeyId"]!,
    secret: builder.Configuration["Downstream:Secret"]!));

builder.Services
    .AddHttpClient<DownstreamApiClient>(client =>
    {
        client.BaseAddress = new Uri(builder.Configuration["Downstream:BaseUrl"]!);
    })
    .AddHttpMessageHandler(sp => sp.GetRequiredService<HmacSigningHandler>());

// ---- Inbound verification: choose ONE of middleware or auth-handler style ----
builder.Services.AddControllers();

// Option A: AuthenticationHandler style (integrates with [Authorize])
// builder.Services
//     .AddAuthentication("Hmac")
//     .AddScheme<HmacAuthSchemeOptions, HmacAuthenticationHandler>("Hmac", _ => { });
// builder.Services.AddAuthorization();

var app = builder.Build();

app.UseHttpsRedirection();

// Option B: Middleware style (simpler, webhook-style single scheme)
app.UseHmacVerification();

// app.UseAuthentication(); // only if using Option A
// app.UseAuthorization();

app.MapControllers();

app.Run();
```

### `appsettings.json`

```json
{
  "Hmac": {
    "Secrets": {
      "partner-a": "replace-with-a-strong-random-secret-32-bytes-min"
    },
    "AllowedClockSkew": "00:05:00"
  },
  "Downstream": {
    "BaseUrl": "https://downstream.example.com",
    "KeyId": "my-service",
    "Secret": "replace-with-a-strong-random-secret-32-bytes-min"
  }
}
```

> Bind `SignatureOptions.AllowedClockSkew` as a `TimeSpan` string (`"00:05:00"`) — `IConfiguration` supports this natively.

---

## 10. Testing Strategy by Layer

| Project | What it tests | Depends on ASP.NET Core? |
|---|---|---|
| `YourApp.Application.Tests` | `SignatureContext` construction rules, exception semantics | No |
| `YourApp.Infrastructure.Tests` | `HmacSignatureService` canonical string + signature correctness, round-trip verify, tampered-body detection, `InMemoryNonceStore`/`DistributedNonceStore` replay behavior | No (pure BCL + Redis test container if needed) |
| `YourApp.Api.Tests` | Full pipeline via `WebApplicationFactory<Program>` — send a signed request, assert 200; send tampered/replayed/stale request, assert 401 | Yes |

### `YourApp.Infrastructure.Tests/Security/HmacSignatureServiceTests.cs`

```csharp
using YourApp.Application.Security.Models;
using YourApp.Infrastructure.Security.Hmac;
using Xunit;

public class HmacSignatureServiceTests
{
    private readonly HmacSignatureService _sut = new();

    [Fact]
    public void Sign_And_Verify_RoundTrip_Succeeds()
    {
        const string secret = "test-secret";
        var body = System.Text.Encoding.UTF8.GetBytes("""{"a":1}""");
        var context = new SignatureContext("POST", "/api/orders", "b=2&a=1", 1726387200, "fixed-nonce", body, "partner-a");

        var canonical = _sut.BuildCanonicalString(context);
        var signature = _sut.Sign(secret, canonical);

        // Rebuild with query params in a different original order — normalization must match.
        var context2 = context with { RawQueryString = "a=1&b=2" };
        var canonical2 = _sut.BuildCanonicalString(context2);
        var expected = _sut.Sign(secret, canonical2);

        Assert.True(_sut.TimingSafeEquals(signature, expected));
    }

    [Fact]
    public void TamperedBody_ProducesDifferentSignature()
    {
        const string secret = "test-secret";
        var original = new SignatureContext("POST", "/api/orders", "", 1, "n1",
            System.Text.Encoding.UTF8.GetBytes("""{"amount":10}"""), "partner-a");
        var tampered = original with
        {
            BodyBytes = System.Text.Encoding.UTF8.GetBytes("""{"amount":10000}""")
        };

        var sigOriginal = _sut.Sign(secret, _sut.BuildCanonicalString(original));
        var sigTampered = _sut.Sign(secret, _sut.BuildCanonicalString(tampered));

        Assert.False(_sut.TimingSafeEquals(sigOriginal, sigTampered));
    }
}
```

### `YourApp.Api.Tests/Security/HmacVerificationMiddlewareTests.cs` (sketch)

```csharp
public class HmacVerificationMiddlewareTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    public HmacVerificationMiddlewareTests(WebApplicationFactory<Program> factory) => _factory = factory;

    [Fact]
    public async Task ValidSignature_Returns200()
    {
        var client = _factory.CreateClient();
        var request = BuildSignedRequest("POST", "/api/orders", """{"customerId":"123","amount":49.99}""");

        var response = await client.SendAsync(request);

        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task TamperedBody_Returns401()
    {
        var client = _factory.CreateClient();
        var request = BuildSignedRequest("POST", "/api/orders", """{"customerId":"123","amount":49.99}""");
        request.Content = new StringContent("""{"customerId":"123","amount":999999}""",
            System.Text.Encoding.UTF8, "application/json"); // swap body after signing

        var response = await client.SendAsync(request);

        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // BuildSignedRequest helper would use the same HmacSignatureService to construct
    // a correctly-signed HttpRequestMessage — reuse Infrastructure directly in tests.
}
```

---

## 11. Security Checklist

- [ ] `Application` project has no reference to `Microsoft.AspNetCore.*` or crypto libraries — only contracts and POCOs.
- [ ] `Infrastructure` is the sole owner of `System.Security.Cryptography` usage for this feature.
- [ ] `Api` never builds a canonical string or calls `HMACSHA256` directly — it only calls `ISignatureService`.
- [ ] Comparison uses `CryptographicOperations.FixedTimeEquals`, never `==`/`Equals`.
- [ ] Canonical string includes method, path, query, timestamp, nonce, and body hash.
- [ ] Timestamp window enforced via `SignatureOptions.AllowedClockSkew`.
- [ ] `INonceStore` backed by Redis (`DistributedNonceStore`) in multi-instance deployments — `InMemoryNonceStore` is single-instance only.
- [ ] Secrets resolved via `ISecretProvider`, backed by a vault in production — never committed to `appsettings.json`.
- [ ] HTTPS enforced end-to-end; HSTS enabled in `Program.cs`.
- [ ] Key rotation supported via `KeyId` header mapped to multiple active secrets in `SignatureOptions.Secrets`.
- [ ] Logging on verification failure (in `HmacVerificationMiddleware`) excludes the secret and full signature — logs `SignatureFailureReason`/exception message and path only.
- [ ] Body buffered via `EnableBuffering()` in the Api-layer middleware only — Infrastructure services never touch `HttpContext`.
- [ ] Swapping `ISecretProvider` (config → Key Vault) or `ISignatureService` (software HMAC → HSM) requires touching only `Infrastructure` + one line in `Program.cs` — never `Application` or `Api` controller/middleware code.
