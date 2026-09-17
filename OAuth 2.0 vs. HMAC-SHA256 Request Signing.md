# Securing ASP.NET Core Web APIs: OAuth 2.0 vs. HMAC-SHA256 Request Signing

When securing an **ASP.NET Core Web API**, choosing between **OAuth 2.0** and **HMAC-SHA256 Request Signing** comes down to whether you need to manage user authorization or secure machine-to-machine data integrity. 

**OAuth 2.0 is an authorization framework** designed to delegate access on behalf of a user or service using short-lived tokens (typically JWTs). **HMAC-SHA256 Request Signing is a cryptographic verification technique** where the client hashes the entire HTTP request payload using a shared secret key to prove the message wasn't tampered with in transit.

---

## Core Differences

| Feature | OAuth 2.0 (JWT) | HMAC-SHA256 Request Signing |
| :--- | :--- | :--- |
| **Primary Purpose** | User/Client Authorization & Delegation | Data Integrity & Request Authenticity |
| **State & Storage** | Requires an Identity Provider or Token Issuer. | Fully stateless; relies entirely on a shared secret key. |
| **Payload Protection** | Validates *who* sent it, but does **not** prevent tampering of the HTTP body. | Validates *what* was sent; fails if a single byte of the request changes. |
| **Replay Attack Defense** | Relies on token expiration (`exp`). Intercepted tokens can be reused until they expire. | Relies on a unique nonce and timestamp window per request. |
| **Performance Overhead** | Low (validating a JWT signature locally). | Higher (server must re-hash the entire request body). |

---

### 1. OAuth 2.0 (Token-Based)
In a typical ASP.NET Core implementation, OAuth 2.0 issues a **JSON Web Token (JWT)**. The client requests a token once, stores it, and attaches it via the `Authorization: Bearer <token>` header for subsequent requests. 

* **Best For:** User-facing applications (Mobile, Single Page Apps like React/Angular) and standard B2B API integrations where you need to enforce granular user permissions (Scopes/Claims).
* **How it works in ASP.NET Core:** Built natively into the framework. You configure the JWT Bearer middleware in `Program.cs`:
  ```csharp
  builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
      .AddJwtBearer(options => { /* validation parameters */ });
  ```
* **The Vulnerability:** If a malicious actor intercepts a valid HTTP POST request, they cannot change the JWT, but they *can* modify the JSON payload (e.g., changing a payment amount from \$10 to \$10,000) and forward it to the server. The JWT remains valid, so the API may process the tampered data unless protected by HTTPS.

---

### 2. HMAC-SHA256 (Request Signing)
Instead of relying on a reusable token, the client hashes specific parts of the request (e.g., HTTP Method, URL, Timestamp, Nonce, and the Request Body) using a **Shared Secret Key**. This hash is sent in a custom header (e.g., `X-Signature`).

* **Best For:** High-security Webhooks, financial transactions, and internal service-to-service communication (Microservices) where data tampering must be strictly impossible.
* **How it works in ASP.NET Core:** You must implement a custom `IMiddleware` or `ActionFilter` to intercept the request, read the raw body stream, compute the hash, and compare it using a constant-time comparison helper:
  ```csharp
  // Server-side verification snippet
  using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(sharedSecret));
  byte[] computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign));
  
  if (!CryptographicOperations.FixedTimeEquals(computedHash, clientProvidedHash)) {
      return Results.Unauthorized(); // 401
  }
  ```
* **The Benefit:** It guarantees **data integrity** and protects against **replay attacks**. If an attacker intercepts the request and tries to execute it again, the server rejects it because the timestamp has expired or the nonce was already used.

---

## Summary Checklist: Which should you choose?

* Choose **OAuth 2.0** if you are building public-facing APIs, need to know *which user* is logging in, or want to utilize standard Identity Providers (like Entra ID, Auth0, or Duende IdentityServer).
* Choose **HMAC-SHA256** if you are building payment gateways, processing webhooks (like Stripe or GitHub), or need absolute certainty that a request payload was not altered between the client and your backend.

---

## The Hybrid Approach: Using Both Together

Using both **OAuth 2.0 and HMAC-SHA256 Request Signing together** creates a defense-in-depth architecture. This hybrid approach combines identity authorization with strict data integrity, commonly used by high-security environments like financial banking systems, payment processors, and healthcare gateways.

When used together, **OAuth 2.0 acts as the passport (who you are)**, while **HMAC-SHA256 acts as the tamper-evident seal on the cargo (what you are sending)**.

### The Request Lifecycle (How They Work Together)

When a client wants to send a sensitive request (e.g., executing a bank wire transfer), the process follows these sequential steps:

1. **The Handshake (OAuth):** The client logs in via an OAuth provider, authenticates, and receives a short-lived **JWT Access Token**. 
2. **The Hashing (HMAC):** The client prepares the API request payload. It takes critical parts of the request (HTTP method, URL, a fresh timestamp, a random unique string/nonce, and the JSON request body) and signs it using a pre-shared secret key to generate a signature.
3. **The HTTP Transmission:** The client fires the request with both security measures attached in the headers:
   ```http
   POST /api/v1/transfers HTTP/1.1
   Host: ://yourbank.com
   Authorization: Bearer eyJhbGciOi... (OAuth JWT Token)
   X-Signature: abcd1234efgh5678... (HMAC Hash)
   X-Timestamp: 2026-09-17T07:36:00Z
   X-Nonce: 9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d

   {
       "sourceAccount": "12345",
       "destinationAccount": "67890",
       "amount": 5000.00
   }
   ```

### How ASP.NET Core Processes the Combined Request

In your ASP.NET Core Web API, the validation pipeline handles these checks sequentially. If any step fails, execution halts immediately.

```text
Incoming Request ──> [ 1. JWT Bearer Middleware ] ──> [ 2. Custom HMAC Middleware ] ──> [ 3. Controller / Minimal API ](Authentication)                (Data Integrity)                  (Business Logic)
```

* **Step 1: Authentication & Scope Verification (JWT Middleware):** The standard ASP.NET Core `JwtBearer` middleware intercepts the request first. It verifies that the token is not expired and is cryptographically signed by your trusted Identity Provider. It extracts user identities and sets the `HttpContext.User`. **What it solves here:** It ensures the entity making the request has the legitimate permission (e.g., `RequiredScope("transfers.write")`) to touch this endpoint.
* **Step 2: Payload & Replay Verification (Custom HMAC Middleware):** Once OAuth passes, your custom HMAC middleware executes. It checks the `X-Timestamp` to ensure the request was generated within an acceptable time window (e.g., within the last 5 minutes) to mitigate replay attempts. It checks the `X-Nonce` against a distributed cache (like Redis) to ensure this exact request string hasn't been submitted twice. It reads the raw JSON body stream, recalculates the HMAC-SHA256 signature using the client's secret key, and compares it to the incoming `X-Signature` header. **What it solves here:** It ensures that an attacker who somehow intercepted the traffic did not alter the payload data, and cannot re-send the exact same packet to drain the account twice.

---

## Full Hybrid Implementation in ASP.NET Core

Here is the complete implementation for an ASP.NET Core API using **both JWT Authentication and custom HMAC Request Signing**. 

### 1. The Program.cs Setup
This setup chains both authentication schemes. The request must first pass the standard **JWT check**, and then hit our **HMAC check**.

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// 1. Add Distributed Cache (e.g., Redis or Memory) to track Nonces and prevent Replay Attacks
builder.Services.AddDistributedMemoryCache();

// 2. Configure Native OAuth 2.0 JWT Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!))
        };
    });

builder.Services.AddAuthorization();

// Register the custom middleware class explicitly in the DI container
builder.Services.AddScoped<HmacValidationMiddleware>();

var app = builder.Build();

app.UseRouting();

// 3. Run OAuth authentication first
app.UseAuthentication();
app.UseAuthorization();

// 4. Inject the Custom HMAC Verification Middleware right after Authorization
app.UseMiddleware<HmacValidationMiddleware>();

// 5. Secure Endpoints
app.MapPost("/api/transfers", () => Results.Ok(new { Message = "Transfer verified and processed safely!" }))
   .RequireAuthorization(); // Requires a valid JWT token

app.Run();
```

### 2. The Custom HMAC Middleware Implementation
This custom middleware extracts the incoming metadata, reads the raw body stream without destroying it for downstream controllers, recalculates the hash, and matches it using a secure, constant-time comparison helper.

```csharp
using Microsoft.Extensions.Caching.Distributed;
using System.Security.Cryptography;
using System.Text;

public class HmacValidationMiddleware : IMiddleware
{
    private readonly IDistributedCache _cache;
    private const string SecretKey = "YourSuperSecretSharedHMACKeyRightHere!"; // Keep this safe (e.g., Azure Key Vault)
    private const int MaxTimestampSkewMinutes = 5;

    public HmacValidationMiddleware(IDistributedCache cache)
    {
        _cache = cache;
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        // Only enforce HMAC on high-value mutating endpoints (e.g., POST/PUT requests)
        if (context.Request.Method != HttpMethods.Post && context.Request.Method != HttpMethods.Put)
        {
            await next(context);
            return;
        }

        // 1. Extract the HMAC metadata headers
        if (!context.Request.Headers.TryGetValue("X-Signature", out var clientSignature) ||
            !context.Request.Headers.TryGetValue("X-Timestamp", out var clientTimestampStr) ||
            !context.Request.Headers.TryGetValue("X-Nonce", out var clientNonce))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("Missing required HMAC headers.");
            return;
        }

        // 2. Prevent Replay Attacks: Check the Timestamp Skew
        if (!DateTime.TryParse(clientTimestampStr, out DateTime clientTimestamp) ||
            Math.Abs((DateTime.UtcNow - clientTimestamp.ToUniversalTime()).TotalMinutes) > MaxTimestampSkewMinutes)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("Request timestamp has expired or is invalid.");
            return;
        }

        // 3. Prevent Replay Attacks: Check and invalidate the Nonce using Cache
        string cacheKey = $"nonce:{clientNonce}";
        var existingNonce = await _cache.GetStringAsync(cacheKey);
        if (existingNonce != null)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("Duplicate request detected (Nonce already used).");
            return;
        }
        
        // Cache the nonce for the length of your expiration window
        await _cache.SetStringAsync(cacheKey, "used", new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(MaxTimestampSkewMinutes)
        });

        // 4. Safely read the HTTP Request Body stream without breaking downstream model binding
        context.Request.EnableBuffering();
        using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
        string requestBody = await reader.ReadToEndAsync();
        context.Request.Body.Position = 0; // Reset stream pointer for the controller

        // 5. Reconstruct the raw signature message structure exactly as the client built it
        string stringToSign = $"{context.Request.Method}\n{context.Request.Path}\n{clientTimestampStr}\n{clientNonce}\n{requestBody}";

        // 6. Compute the server-side HMAC-SHA256 signature
        byte[] secretBytes = Encoding.UTF8.GetBytes(SecretKey);
        using var hmac = new HMACSHA256(secretBytes);
        byte[] computedHashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign));
        string serverSignature = Convert.ToHexString(computedHashBytes).ToLower();

        // 7. Use a constant-time comparison to prevent timing attacks
        byte[] clientSigBytes = Encoding.UTF8.GetBytes(clientSignature.ToString().ToLower());
        byte[] serverSigBytes = Encoding.UTF8.GetBytes(serverSignature);

        if (!CryptographicOperations.FixedTimeEquals(clientSigBytes, serverSigBytes))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("Invalid signature. Payload data tampering detected.");
            return;
        }

        await next(context);
    }
}
```

### 3. Signature Construction Rule
For this configuration to succeed, your client applications must construct the `stringToSign` exactly the same way before generating their payload hash. They should join the properties together using a standard delimiter (like newlines `\n`):

\[\text{Signature} = \text{HMAC-SHA256}(\text{Method} + \text{"}\backslash\text{n"} + \text{Path} + \text{"}\backslash\text{n"} + \text{Timestamp} + \text{"}\backslash\text{n"} + \text{Nonce} + \text{"}\backslash\text{n"} + \text{Body}, \text{ SecretKey})\]

# Client-Side Implementation: Generating the Request Signature

Here are the two most common ways to implement the client-side signature generation to test your hybrid ASP.NET Core API. The payload signature must exactly match the formatting rule expected by the server: `Method + \n + Path + \n + Timestamp + \n + Nonce + \n + Body`.

---

### 1. C# HttpClient Implementation
This is the code your backend microservices or desktop clients will use to sign requests before transmitting them to your API.

```csharp
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

public class SecureApiClient
{
    private readonly HttpClient _httpClient;
    private const string SecretKey = "YourSuperSecretSharedHMACKeyRightHere!";

    public SecureApiClient(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<string> SendSecureTransferAsync(string jwtToken, object transferPayload)
    {
        string url = "https://localhost:7001/api/transfers";
        string path = "/api/transfers";
        string method = "POST";
        
        // 1. Generate Metadata
        string timestamp = DateTime.UtcNow.ToString("o"); // ISO 8601 Format
        string nonce = Guid.NewGuid().ToString();
        string jsonBody = JsonSerializer.Serialize(transferPayload);

        // 2. Construct the raw string to sign (Exactly matching server format)
        string stringToSign = \$"{method}\n{path}\n{timestamp}\n{nonce}\n{jsonBody}";

        // 3. Compute HMAC-SHA256 Hash
        byte[] secretBytes = Encoding.UTF8.GetBytes(SecretKey);
        using var hmac = new HMACSHA256(secretBytes);
        byte[] hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign));
        string signature = Convert.ToHexString(hashBytes).ToLower();

        // 4. Build HTTP Request
        var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");

        // 5. Attach Security Headers
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", jwtToken); // OAuth 2.0
        request.Headers.Add("X-Signature", signature);                                    // HMAC
        request.Headers.Add("X-Timestamp", timestamp);
        request.Headers.Add("X-Nonce", nonce);

        // 6. Execute Request
        var response = await _httpClient.SendAsync(request);
        return await response.Content.ReadAsStringAsync();
    }
}
```

---

### 2. Postman Pre-request Script
For rapid testing or manual QA, you can place this JavaScript code inside the **Pre-request Script** tab of your Postman request. It automatically updates your collection variables and appends the necessary signature elements instantly right before firing.

```javascript
// 1. Define configuration settings
const secretKey = "YourSuperSecretSharedHMACKeyRightHere!";
const path = pm.request.url.getPath(); // Extracts e.g., "/api/transfers"
const method = pm.request.method;

// 2. Generate Nonce and Timestamp
const nonce = crypto.randomUUID();
const timestamp = new Date().toISOString();

// 3. Capture the raw JSON Request Body
const rawBody = pm.request.body.raw ? pm.request.body.raw.trim() : "";

// 4. Construct the signature payload layout matching the server delimiter rule
const stringToSign = `${method}\n{path}\n{timestamp}\n{nonce}\n{rawBody}`;

// 5. Compute HMAC-SHA256 hash using CryptoJS (Built natively into Postman)
const hash = cryptoJS.HmacSHA256(stringToSign, secretKey);
const signature = cryptoJS.enc.Hex.stringify(hash).toLowerCase();

// 6. Set Postman variables dynamically to be mapped onto your headers
pm.variables.set("hmac_signature", signature);
pm.variables.set("hmac_timestamp", timestamp);
pm.variables.set("hmac_nonce", nonce);
```

#### How to configure the Headers tab inside Postman:
Map the calculated script variables into your HTTP request header template like this:

| Key | Value |
| :--- | :--- |
| **Authorization** | `Bearer {{oauth_jwt_token}}` |
| **X-Signature** | `{{hmac_signature}}` |
| **X-Timestamp** | `{{hmac_timestamp}}` |
| **X-Nonce** | `{{hmac_nonce}}` |
