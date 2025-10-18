using System.IO;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.DependencyInjection;
using System.Collections.Concurrent;
using System.Net.Http;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text;
using System;
using System.Linq;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<CacheService>();
builder.Services.AddHttpClient();
var app = builder.Build();

string staticDir = Path.Combine(Directory.GetCurrentDirectory(), "static");
string tmpDir = Path.Combine(Directory.GetCurrentDirectory(), "tmp");
Directory.CreateDirectory(staticDir);
Directory.CreateDirectory(tmpDir);

var secretKey = "SuperSecretKey123!"; 

app.MapGet("/", () => "MiniCDN is running");


app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new PhysicalFileProvider(staticDir),
    RequestPath = ""
});


app.MapGet("/list-cache", (CacheService cache) => Results.Json(cache.List()));


app.MapGet("/fetch", async (HttpContext context, IHttpClientFactory clientFactory, CacheService cache) =>
{
    var url = context.Request.Query["url"].ToString();
    var forShare = context.Request.Query["forShare"].ToString();
    var cacheParam = context.Request.Query["cache"].ToString()?.ToLower();

    if (string.IsNullOrEmpty(url))
        return Results.BadRequest("Missing url parameter");

    var fileName = Path.GetFileName(new Uri(url).LocalPath);
    string folder = string.IsNullOrEmpty(forShare) ? staticDir : tmpDir;
    var cachePath = Path.Combine(folder, fileName);

    // ✅ Default: cache = true
    bool shouldCache = cacheParam != "false";

    // Use existing cache if valid
    if (shouldCache && cache.IsCached(cachePath))
    {
        if (!string.IsNullOrEmpty(forShare))
        {
            var token = TokenUtils.CreateSignedToken(fileName, secretKey, 15);
            var link = $"/share/{token}";
            return Results.Ok(new { link });
        }
        return Results.File(cachePath);
    }

    // Download file
    var client = clientFactory.CreateClient();
    var data = await client.GetByteArrayAsync(url);

    // Write to cache (if enabled)
    if (shouldCache)
    {
        await File.WriteAllBytesAsync(cachePath, data);
        var duration = TimeSpan.FromMinutes(string.IsNullOrEmpty(forShare) ? 30 : 15);
        cache.Add(cachePath, duration);
    }

    // Create shared link if requested
    if (!string.IsNullOrEmpty(forShare))
    {
        var token = TokenUtils.CreateSignedToken(fileName, secretKey, 15);
        var link = $"/share/{token}";
        return Results.Ok(new { link });
    }

    // Return file (cached or streamed)
    return Results.File(data, "application/octet-stream", fileName);
});

// Access shared file via signed link
app.MapGet("/share/{token}", (string token) =>
{
    var info = TokenUtils.ValidateSignedToken(token, secretKey);
    if (info == null)
        return Results.Unauthorized();

    var filePath = Path.Combine(tmpDir, info.FileName);
    if (!File.Exists(filePath))
        return Results.NotFound();

    return Results.File(filePath);
});

app.Run();

/// <summary>
/// Simple timed file cache
/// </summary>
public class CacheService
{
    private readonly ConcurrentDictionary<string, DateTime> _cache = new();

    public CacheService()
    {
        _ = CleanupLoop();
    }

    public void Add(string path, TimeSpan duration)
    {
        _cache[path] = DateTime.UtcNow.Add(duration);
    }

    public bool IsCached(string path)
    {
        return File.Exists(path) && _cache.TryGetValue(path, out var exp) && exp > DateTime.UtcNow;
    }

    public object List()
    {
        return _cache.Select(kv => new
        {
            file = Path.GetFileName(kv.Key),
            expires = kv.Value
        });
    }

    private async Task CleanupLoop()
    {
        while (true)
        {
            foreach (var item in _cache)
            {
                if (item.Value < DateTime.UtcNow)
                {
                    try { File.Delete(item.Key); } catch { }
                    _cache.TryRemove(item.Key, out _);
                }
            }
            await Task.Delay(TimeSpan.FromMinutes(1));
        }
    }
}


public record ShareInfo(string FileName, DateTime ExpireAt);

public static class TokenUtils
{
    public static string CreateSignedToken(string fileName, string secret, int expireMinutes)
    {
        var exp = DateTimeOffset.UtcNow.AddMinutes(expireMinutes).ToUnixTimeSeconds();
        var raw = $"{fileName}|{exp}";
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var sig = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(raw)));
        var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{fileName}|{exp}|{sig}"));
        return token.Replace('+', '-').Replace('/', '_').TrimEnd('='); // URL safe
    }

    public static ShareInfo? ValidateSignedToken(string token, string secret)
    {
        try
        {
            token = token.Replace('-', '+').Replace('_', '/');
            var padded = token.PadRight(token.Length + (4 - token.Length % 4) % 4, '=');
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(padded));
            var parts = decoded.Split('|');
            if (parts.Length != 3) return null;

            var fileName = parts[0];
            var exp = DateTimeOffset.FromUnixTimeSeconds(long.Parse(parts[1])).UtcDateTime;
            if (DateTime.UtcNow > exp) return null;

            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
            var expectedSig = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes($"{fileName}|{parts[1]}")));

            if (expectedSig != parts[2]) return null;

            return new ShareInfo(fileName, exp);
        }
        catch
        {
            return null;
        }
    }
}
//
// /fetch?url=https://example.com/img.png/fetch?url=https://example.com/img.png
// /fetch?url=https://example.com/img.png&cache=true
// /fetch?url=https://example.com/img.png&cache=false
// /fetch?url=https://example.com/img.png&forShare=x
// /share/{token}
// /list-cache
//
//
// FROM mcr.microsoft.com/dotnet/aspnet:8.0
// WORKDIR / app
// COPY. .
// EXPOSE 80
// ENTRYPOINT["dotnet", "MiniCDN.dll"]
//