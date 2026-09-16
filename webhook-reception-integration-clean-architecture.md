# Integrating Webhook Reception into Your Clean Architecture HMAC Solution

This builds directly on `YourApp.Domain / Application / Infrastructure / Api`. It reuses what already exists (`ISecretProvider`, timing-safe comparison patterns, the layering rules) and adds only what's new: **provider signature verification, idempotent event storage, and async processing** — each placed per your existing "does this know about HTTP?" rule.

---

## 1. Why this doesn't just plug into `HmacVerificationMiddleware`

| Your internal scheme | Incoming webhooks (Stripe/GitHub/etc.) |
|---|---|
| You control both signer and verifier | Provider signs, you only verify |
| Headers: `X-Signature`, `X-Signature-Timestamp`, `X-Signature-Nonce`, `X-Signature-KeyId` | Provider-defined headers (`Stripe-Signature`, `X-Hub-Signature-256`, ...) |
| Canonical string includes nonce (replay protection is a *header field*) | No nonce — replay protection is your own dedupe-by-event-ID, not part of the signature |
| One scheme for the whole API | **One scheme per provider** — you may integrate several providers, each with its own verifier |

Conclusion: keep `HmacVerificationMiddleware` exactly as-is for your own API surface, and add a **separate, narrower pipeline** for `/webhooks/*` that never runs `UseHmacVerification()`.

---

## 2. New pieces, placed by your existing rule

| Concern | Layer | Reuses |
|---|---|---|
| `IWebhookSignatureVerifier` contract, `WebhookVerificationOutcome`, dedupe/processing status enum | **Application** (`Security/Webhooks/`) | Same pattern as `ISignatureService` / `SignatureVerificationOutcome` |
| `IWebhookEventStore` contract (record + dedupe) | **Application** | New interface, same folder convention as `INonceStore` |
| `IWebhookProcessor` contract (per event-type business handling) | **Application** | — |
| Per-provider HMAC implementations (`StripeWebhookVerifier`, `GitHubWebhookVerifier`, ...) | **Infrastructure** (`Security/Webhooks/`) | `CryptographicOperations.FixedTimeEquals`, and can resolve secrets via your existing `ISecretProvider` |
| EF Core `WebhookEventStore` (unique index dedupe) | **Infrastructure** | Same `AppDbContext` you already have |
| In-process queue + `BackgroundService` (or Service Bus/SQS publisher) | **Infrastructure** | New — this is transport/runtime plumbing, same category as `HmacSigningHandler` |
| Minimal API endpoint that reads raw body, calls verifier, persists, ACKs | **Api** (`Controllers/WebhooksController.cs` or a minimal-API module) | Same adapter role as `HmacVerificationMiddleware`, but a controller/endpoint instead of middleware since it's a single dedicated route, not a cross-cutting pipeline step |
| DI wiring + route registration | **Api** (`Program.cs`) | — |

`YourApp.Domain` stays untouched, same as with the original HMAC feature — webhook plumbing is transport security, not a business invariant.

---

## 3. Application Layer — new contracts

### `Security/Webhooks/Interfaces/IWebhookSignatureVerifier.cs`

```csharp
namespace YourApp.Application.Security.Webhooks.Interfaces;

/// <summary>
/// One implementation per provider (Stripe, GitHub, Shopify, ...). Verifies the raw
/// request body against a provider-supplied signature header. No knowledge of
/// HttpContext — the Api layer extracts the raw body and header value and passes them in.
/// </summary>
public interface IWebhookSignatureVerifier
{
    /// <summary>Matches this verifier to the incoming route/provider, e.g. "stripe".</summary>
    string ProviderKey { get; }

    bool IsValid(string rawBody, IReadOnlyDictionary<string, string> headers);
}
```

### `Security/Webhooks/Interfaces/IWebhookEventStore.cs`

```csharp
namespace YourApp.Application.Security.Webhooks.Interfaces;

/// <summary>
/// Records an inbound webhook event, keyed by the provider's own event ID.
/// Returns false if the event ID was already recorded (duplicate delivery).
/// </summary>
public interface IWebhookEventStore
{
    Task<bool> TryRecordAsync(string providerKey, string eventId, string rawPayload, CancellationToken ct = default);
}
```

### `Security/Webhooks/Interfaces/IWebhookProcessor.cs`

```csharp
namespace YourApp.Application.Security.Webhooks.Interfaces;

/// <summary>
/// Business-side handling of a stored webhook event. Implemented per provider (or
/// per event-type) and invoked asynchronously by the Infrastructure worker.
/// </summary>
public interface IWebhookProcessor
{
    string ProviderKey { get; }
    Task ProcessAsync(string eventId, string rawPayload, CancellationToken ct = default);
}
```

### `Security/Webhooks/Exceptions/WebhookSignatureException.cs`

```csharp
namespace YourApp.Application.Security.Webhooks.Exceptions;

public sealed class WebhookSignatureException(string providerKey)
    : Exception($"Signature verification failed for provider '{providerKey}'.");

public sealed class UnknownWebhookProviderException(string providerKey)
    : Exception($"No signature verifier registered for provider '{providerKey}'.");
```

These mirror `SignatureException`/`UnknownSigningKeyException` from your existing internal scheme — same reasoning: "an unverifiable webhook" is a business-relevant outcome independent of ASP.NET Core.

---

## 4. Infrastructure Layer — per-provider verifiers + storage

### `Security/Webhooks/StripeWebhookVerifier.cs`

```csharp
using System.Security.Cryptography;
using System.Text;
using YourApp.Application.Security.Interfaces;      // your existing ISecretProvider
using YourApp.Application.Security.Webhooks.Interfaces;

namespace YourApp.Infrastructure.Security.Webhooks;

public sealed class StripeWebhookVerifier(ISecretProvider secretProvider) : IWebhookSignatureVerifier
{
    public string ProviderKey => "stripe";

    private static readonly TimeSpan ToleranceWindow = TimeSpan.FromMinutes(5);

    public bool IsValid(string rawBody, IReadOnlyDictionary<string, string> headers)
    {
        if (!headers.TryGetValue("Stripe-Signature", out var header))
            return false;

        // Format: t=1726387200,v1=<hex>
        var parts = header.Split(',')
            .Select(p => p.Split('=', 2))
            .Where(kv => kv.Length == 2)
            .ToDictionary(kv => kv[0], kv => kv[1]);

        if (!parts.TryGetValue("t", out var tRaw) || !parts.TryGetValue("v1", out var providedSig))
            return false;

        if (!long.TryParse(tRaw, out var timestamp))
            return false;

        var age = DateTimeOffset.UtcNow - DateTimeOffset.FromUnixTimeSeconds(timestamp);
        if (age.Duration() > ToleranceWindow)
            return false; // replay/staleness guard — Stripe's own scheme, not your nonce store

        // Secret resolved via your EXISTING ISecretProvider — reuse it, just a different KeyId namespace.
        var secret = secretProvider.GetSecretAsync($"webhook:{ProviderKey}").GetAwaiter().GetResult()
            ?? throw new InvalidOperationException("Stripe webhook secret not configured.");

        var signedPayload = $"{tRaw}.{rawBody}";
        var computed = Convert.ToHexStringLower(
            HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(signedPayload)));

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(computed),
            Encoding.UTF8.GetBytes(providedSig));
    }
}
```

> Notice this **reuses `ISecretProvider`** from your existing Application contract instead of inventing a new secret-resolution path — that's the payoff of having pulled secret access behind an interface already. Just give webhook secrets their own `KeyId` namespace (`webhook:stripe`, `webhook:github`, ...) in `SignatureOptions.Secrets` or a sibling options class.

### `Security/Webhooks/GitHubWebhookVerifier.cs` (second provider, same pattern)

```csharp
public sealed class GitHubWebhookVerifier(ISecretProvider secretProvider) : IWebhookSignatureVerifier
{
    public string ProviderKey => "github";

    public bool IsValid(string rawBody, IReadOnlyDictionary<string, string> headers)
    {
        if (!headers.TryGetValue("X-Hub-Signature-256", out var header))
            return false;

        var secret = secretProvider.GetSecretAsync($"webhook:{ProviderKey}").GetAwaiter().GetResult();
        if (secret is null) return false;

        var computed = "sha256=" + Convert.ToHexStringLower(
            HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(rawBody)));

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(computed), Encoding.UTF8.GetBytes(header));
    }
}
```

Registering multiple `IWebhookSignatureVerifier` implementations and resolving the right one by `ProviderKey` (via `IEnumerable<IWebhookSignatureVerifier>` + a small resolver, or keyed DI in .NET 10 — see §6) is what lets you add a third provider later without touching the Api layer.

### `Security/Webhooks/WebhookEventStore.cs` (EF Core, same `AppDbContext`)

```csharp
using Microsoft.EntityFrameworkCore;
using YourApp.Application.Security.Webhooks.Interfaces;

namespace YourApp.Infrastructure.Security.Webhooks;

public sealed class WebhookEventStore(AppDbContext db) : IWebhookEventStore
{
    public async Task<bool> TryRecordAsync(string providerKey, string eventId, string rawPayload, CancellationToken ct = default)
    {
        db.WebhookEvents.Add(new WebhookEventEntity
        {
            ProviderKey = providerKey,
            EventId = eventId,
            Payload = rawPayload,
            ReceivedAt = DateTimeOffset.UtcNow,
            Status = WebhookProcessingStatus.Pending
        });

        try
        {
            await db.SaveChangesAsync(ct);
            return true;
        }
        catch (DbUpdateException)
        {
            return false; // unique (ProviderKey, EventId) constraint hit — duplicate delivery
        }
    }
}
```

```csharp
// Configure in AppDbContext.OnModelCreating:
modelBuilder.Entity<WebhookEventEntity>()
    .HasIndex(e => new { e.ProviderKey, e.EventId })
    .IsUnique();
```

### `Security/Webhooks/WebhookProcessingQueue.cs` + worker

Same channel-based pattern as a plain-ASP.NET-Core setup, just placed in Infrastructure since it's runtime/queueing plumbing, and it resolves `IWebhookProcessor` (an Application contract) per provider inside a DI scope:

```csharp
public sealed class WebhookProcessingQueue
{
    private readonly Channel<(string ProviderKey, string EventId)> _channel = Channel.CreateUnbounded<(string, string)>();
    public void Enqueue(string providerKey, string eventId) => _channel.Writer.TryWrite((providerKey, eventId));
    public ChannelReader<(string ProviderKey, string EventId)> Reader => _channel.Reader;
}

public sealed class WebhookProcessingWorker(
    WebhookProcessingQueue queue,
    IServiceScopeFactory scopeFactory,
    ILogger<WebhookProcessingWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var (providerKey, eventId) in queue.Reader.ReadAllAsync(stoppingToken))
        {
            using var scope = scopeFactory.CreateScope();
            var processors = scope.ServiceProvider.GetServices<IWebhookProcessor>();
            var processor = processors.FirstOrDefault(p => p.ProviderKey == providerKey);

            if (processor is null)
            {
                logger.LogWarning("No processor registered for provider {Provider}", providerKey);
                continue;
            }

            try
            {
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                var entity = await db.WebhookEvents.SingleAsync(
                    e => e.ProviderKey == providerKey && e.EventId == eventId, stoppingToken);

                await processor.ProcessAsync(eventId, entity.Payload, stoppingToken);

                entity.Status = WebhookProcessingStatus.Succeeded;
                await db.SaveChangesAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed processing {Provider}/{EventId}", providerKey, eventId);
                // mark Failed / increment attempts / dead-letter — same as the generic guide, §6
            }
        }
    }
}
```

For production durability, swap `WebhookProcessingQueue` for a publisher to Azure Service Bus/SQS — the *interface Api calls* (`Enqueue`) stays identical, so nothing above it changes.

---

## 5. Api Layer — the endpoint, deliberately bypassing `HmacVerificationMiddleware`

Since `app.UseHmacVerification()` runs globally, either:

**A. Branch the pipeline** so webhook routes skip it (cleanest):

```csharp
app.MapWhen(
    ctx => !ctx.Request.Path.StartsWithSegments("/webhooks"),
    branch => branch.UseHmacVerification());
```

Everything under `/webhooks/*` never enters your internal-scheme middleware; everything else keeps working exactly as documented in your README.

**B. Or keep the middleware global but have it short-circuit for `/webhooks/*` paths** if you'd rather not restructure the pipeline — a one-line path check at the top of `InvokeAsync`. (A) is preferable because it keeps `HmacVerificationMiddleware` free of routing knowledge, consistent with your "Api never knows about unrelated concerns" layering intent.

### `Controllers/WebhooksController.cs`

```csharp
using Microsoft.AspNetCore.Mvc;
using YourApp.Application.Security.Webhooks.Interfaces;
using YourApp.Application.Security.Webhooks.Exceptions;

namespace YourApp.Api.Controllers;

[ApiController]
[Route("webhooks/{provider}")]
public sealed class WebhooksController(
    IEnumerable<IWebhookSignatureVerifier> verifiers,
    IWebhookEventStore eventStore,
    WebhookProcessingQueue queue,
    ILogger<WebhooksController> logger) : ControllerBase
{
    [HttpPost]
    [RequestSizeLimit(1_048_576)]
    public async Task<IActionResult> Receive(string provider, CancellationToken ct)
    {
        var verifier = verifiers.FirstOrDefault(v => v.ProviderKey == provider);
        if (verifier is null)
            throw new UnknownWebhookProviderException(provider);

        Request.EnableBuffering();
        using var reader = new StreamReader(Request.Body, leaveOpen: true);
        var rawBody = await reader.ReadToEndAsync(ct);
        Request.Body.Position = 0;

        var headers = Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString());

        if (!verifier.IsValid(rawBody, headers))
        {
            logger.LogWarning("Webhook signature verification failed for {Provider}", provider);
            throw new WebhookSignatureException(provider);
        }

        var eventId = ExtractEventId(provider, headers, rawBody); // provider-specific header/body extraction

        var isNew = await eventStore.TryRecordAsync(provider, eventId, rawBody, ct);
        if (isNew)
            queue.Enqueue(provider, eventId);

        return Ok(); // 200 whether new or duplicate — provider should stop retrying either way
    }

    private static string ExtractEventId(string provider, Dictionary<string, string> headers, string rawBody) =>
        provider switch
        {
            "github" => headers.GetValueOrDefault("X-GitHub-Delivery", Guid.NewGuid().ToString()),
            "stripe" => System.Text.Json.JsonDocument.Parse(rawBody).RootElement.GetProperty("id").GetString()!,
            _ => throw new UnknownWebhookProviderException(provider)
        };
}
```

Map `WebhookSignatureException` → 401 and `UnknownWebhookProviderException` → 404 the same way your `HmacVerificationMiddleware` translates `SignatureException` → 401 — either a small exception-filter/middleware in Api, or an `[ExceptionFilter]` on this controller, keeping the "Api translates Application exceptions to HTTP" rule intact.

### `Program.cs` additions

```csharp
// ---- Webhook verifiers (Infrastructure implementations of Application contract) ----
builder.Services.AddSingleton<IWebhookSignatureVerifier, StripeWebhookVerifier>();
builder.Services.AddSingleton<IWebhookSignatureVerifier, GitHubWebhookVerifier>();

// ---- Webhook storage + processing ----
builder.Services.AddScoped<IWebhookEventStore, WebhookEventStore>();
builder.Services.AddSingleton<WebhookProcessingQueue>();
builder.Services.AddHostedService<WebhookProcessingWorker>();

// ---- Per-provider business processors (implemented wherever your use cases live, likely Application/Infrastructure) ----
builder.Services.AddScoped<IWebhookProcessor, StripeEventProcessor>();
builder.Services.AddScoped<IWebhookProcessor, GitHubEventProcessor>();

builder.Services.AddControllers();

var app = builder.Build();

app.UseHttpsRedirection();

// Branch: internal-scheme middleware skips /webhooks/*
app.MapWhen(
    ctx => !ctx.Request.Path.StartsWithSegments("/webhooks"),
    branch => branch.UseHmacVerification());

app.MapControllers();
app.Run();
```

### `appsettings.json` addition

```json
{
  "Hmac": {
    "Secrets": {
      "partner-a": "existing-internal-secret",
      "webhook:stripe": "whsec_...",
      "webhook:github": "replace-with-github-webhook-secret"
    }
  }
}
```

Reusing `SignatureOptions.Secrets`/`ConfigurationSecretProvider` for webhook secrets works because `ISecretProvider.GetSecretAsync(keyId)` doesn't care what the KeyId namespace means — same interface, no new plumbing. Swapping to Key Vault later covers both internal and webhook secrets simultaneously, for free.

---

## 6. Where this diverges from a plain (non-Clean-Architecture) setup

- **Signature verification logic never touches `HttpContext`** — `IWebhookSignatureVerifier.IsValid` takes `rawBody` + a plain header dictionary, so it's testable exactly like `HmacSignatureService` in your existing `Application.Tests`/`Infrastructure.Tests` split.
- **Dedupe and processing status live behind an Application interface** (`IWebhookEventStore`), so you can swap EF Core for a different store without touching the controller — same principle as `ISecretProvider`.
- **Provider resolution is open for extension**: adding a third provider means one new `IWebhookSignatureVerifier` + one new `IWebhookProcessor` + two DI lines — `WebhooksController` and `WebhookProcessingWorker` don't change. If you'd rather avoid the `IEnumerable<T>.FirstOrDefault` lookup, .NET's **keyed DI** (`AddKeyedSingleton<IWebhookSignatureVerifier>("stripe", ...)` / `[FromKeyedServices("stripe")]`) is a clean alternative available in modern .NET.

---

## 7. Testing additions (fits your existing three-project split)

| Project | New tests |
|---|---|
| `YourApp.Application.Tests` | `WebhookSignatureException`/`UnknownWebhookProviderException` semantics (no ASP.NET Core needed) |
| `YourApp.Infrastructure.Tests` | `StripeWebhookVerifier`/`GitHubWebhookVerifier` against each provider's **published test vectors**; `WebhookEventStore` duplicate-insert returns `false` |
| `YourApp.Api.Tests` | `WebApplicationFactory` test posting a correctly-signed Stripe payload → 200 + row persisted; same payload posted twice → second call still 200 but no duplicate processing; tampered body → 401; confirm requests to `/api/orders` still go through `HmacVerificationMiddleware` unaffected by the `MapWhen` branch |

---

## 8. Worked Example — A Single Stripe Delivery, End to End

This walks through one real `payment_intent.succeeded` delivery so the moving parts in §4/§5 above have something concrete to anchor to.

### 8.1 The secret

When you connect a webhook endpoint in the Stripe dashboard (or via API), Stripe issues a **signing secret**:

```
whsec_5f4a1b8c9d2e3f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a
```

Stored under the `webhook:stripe` KeyId namespace introduced in §5:

```json
"Hmac": {
  "Secrets": {
    "webhook:stripe": "whsec_5f4a1b8c9d2e3f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a"
  }
}
```

### 8.2 What Stripe actually sends

**Headers:**
```
Content-Type: application/json
Stripe-Signature: t=1758012345,v1=8a3f2e1c9b7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f
```

**Raw body** (the exact byte sequence matters — never a re-serialized version):
```json
{"id":"evt_1PxJ8k2eZvKYlo2C9x8QW1zA","object":"event","type":"payment_intent.succeeded","created":1758012345,"data":{"object":{"id":"pi_3PxJ8k2eZvKYlo2C0xYzAbCd","amount":2000,"currency":"usd","status":"succeeded"}}}
```

### 8.3 How `Stripe-Signature` is constructed (what the verifier reverses)

| Part | Value | Meaning |
|---|---|---|
| `t=1758012345` | Unix timestamp | When Stripe signed this |
| `v1=8a3f2e1c...` | Hex HMAC-SHA256 | The signature |

Stripe computes the signature over a **signed_payload string** — timestamp and raw body joined with a dot, not just the raw body alone:

```
signed_payload = "{timestamp}.{raw_body}"
                = "1758012345.{\"id\":\"evt_1PxJ8k2eZvKYlo2C9x8QW1zA\",...}"

v1 = HMAC-SHA256(secret, signed_payload)   // hex-encoded
```

This is exactly what `StripeWebhookVerifier.IsValid` (§4) reconstructs:

```csharp
var signedPayload = $"{tRaw}.{rawBody}";
var computed = Convert.ToHexStringLower(
    HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(signedPayload)));
```

If `computed == providedSig` (compared via `CryptographicOperations.FixedTimeEquals`) the request genuinely came from Stripe and the body wasn't altered in transit.

### 8.4 Manually reproducing the signature (sanity check / local testing)

Useful for confirming your verifier is doing what you think, or for crafting a signed test request by hand:

```bash
BODY='{"id":"evt_1PxJ8k2eZvKYlo2C9x8QW1zA","object":"event","type":"payment_intent.succeeded","created":1758012345,"data":{"object":{"id":"pi_3PxJ8k2eZvKYlo2C0xYzAbCd","amount":2000,"currency":"usd","status":"succeeded"}}}'
TS=1758012345
SECRET="whsec_5f4a1b8c9d2e3f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a"

echo -n "${TS}.${BODY}" | openssl dgst -sha256 -hmac "$SECRET"
```

Whatever hex string prints is what should appear after `v1=` for that exact body + timestamp + secret combination. Change a single character in `$BODY` and the output changes completely — that's the tamper-detection property your verifier is checking for.

### 8.5 What happens once verification passes

1. `eventId` is extracted from the JSON body's `id` field (per `WebhooksController.ExtractEventId`, §5) → `evt_1PxJ8k2eZvKYlo2C9x8QW1zA`.
2. `WebhookEventStore.TryRecordAsync("stripe", "evt_1PxJ8k2eZvKYlo2C9x8QW1zA", rawBody)` inserts a row. If Stripe retries this same event (timeout, network blip on their side), the second insert violates the unique `(ProviderKey, EventId)` index, `TryRecordAsync` returns `false`, and nothing is double-processed.
3. The controller returns `200 OK` either way — new or duplicate.
4. If it was new, `queue.Enqueue("stripe", eventId)` — `WebhookProcessingWorker` later dequeues it and hands it to whichever `IWebhookProcessor` has `ProviderKey == "stripe"` for the actual business logic (e.g., marking an order paid).

### 8.6 Where the real secret comes from in practice

You won't type `whsec_...` by hand in production — Stripe shows it once when you create the endpoint (Dashboard → Developers → Webhooks → your endpoint → "Reveal signing secret"), or it comes back from the API when creating a `WebhookEndpoint` object.

For **local development**, the Stripe CLI generates a temporary secret scoped to that session:

```bash
stripe listen --forward-to localhost:5001/webhooks/stripe
# prints: Ready! Your webhook signing secret is whsec_... (^C to quit)
```

Drop that value into `appsettings.Development.json` or user-secrets for the duration of local testing — it's different from (and shouldn't be confused with) the production endpoint's secret.

---

## 9. Checklist to add to your existing §11

- [ ] `/webhooks/*` is excluded from `HmacVerificationMiddleware` via `MapWhen` (or an explicit path check) — verified by a test that a request with *no* internal-scheme headers still reaches the webhook controller.
- [ ] Each `IWebhookSignatureVerifier` reads the **raw buffered body**, never a re-serialized/model-bound version.
- [ ] Webhook secrets live in the same `ISecretProvider` abstraction, under a distinct `webhook:{provider}` KeyId namespace — not hardcoded, not reusing the internal-scheme secret.
- [ ] Dedupe key is the **provider's** event ID (`X-GitHub-Delivery`, Stripe's `id` field, etc.), never a GUID you generate.
- [ ] `(ProviderKey, EventId)` has a unique index — duplicate delivery is caught by the database, not by an in-memory check.
- [ ] Controller returns `200` for both new and duplicate deliveries — never propagate a processing failure back as the HTTP response status.
- [ ] Async processing failures are retried/dead-lettered inside `WebhookProcessingWorker`, decoupled from the HTTP response already sent.
