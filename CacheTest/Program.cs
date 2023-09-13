using Microsoft.Identity.Web;
using Microsoft.Identity.Client;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Caching.Memory;
using System.Diagnostics;
using Microsoft.Identity.Web.TokenCacheProviders.InMemory;

var audience = "c880d6fb-5c66-49ef-9cf5-e53e31900be5";
var tenant = "f8cdef31-a31e-4b4a-93e4-5f571e91255a";
var appId = "247616d9-2f1a-4440-bf44-c5dcfb2340bf";
var tokenFormat = "https://login.microsoftonline.com/{0}";
var authority = new Uri(string.Format(tokenFormat, tenant));
var secret = "fK8Qcr1zpjGwYDJWJPS3mex";

var app = ConfidentialClientApplicationBuilder.Create(appId)
    .WithAuthority(authority)
    .WithClientSecret(secret)
    .WithLegacyCacheCompatibility(false)
    .Build();

app.AddInMemoryTokenCache(services =>
{
    services.Configure<MemoryCacheOptions>(options =>
    {
        options.SizeLimit = 500 * 1024;
    });
    services.Configure<MsalMemoryTokenCacheOptions>(options =>
    {
        options.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5);
    });
});

var scopes = new string[] { $"{audience.TrimEnd('/')}/.default" };

var firstCert = await app.AcquireTokenForClient(scopes).ExecuteAsync().ConfigureAwait(false);

Console.WriteLine($"Original Token acquired at {DateTimeOffset.Now} expires on: {firstCert.ExpiresOn.ToLocalTime()}");
Console.WriteLine();

for (int i = 0; i < 20; i++)
{
    var secondApp = ConfidentialClientApplicationBuilder.Create(appId)
    .WithAuthority(authority)
    .WithClientSecret(secret)
    .WithLegacyCacheCompatibility(false)
    .Build();

    secondApp.AddInMemoryTokenCache(services =>
    {
        services.Configure<MemoryCacheOptions>(options =>
        {
            options.SizeLimit = 500 * 1024;
        });
        services.Configure<MsalMemoryTokenCacheOptions>(options =>
        {
            options.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5);
        });
    });

    await Task.Delay(TimeSpan.FromMinutes(1));
    Stopwatch stopwatch = new Stopwatch();
    stopwatch.Start();
    var secondCert = await secondApp.AcquireTokenForClient(scopes).ExecuteAsync().ConfigureAwait(false);
    stopwatch.Stop();
    Console.WriteLine(secondCert.ExpiresOn.ToLocalTime());
    Console.WriteLine(stopwatch.ElapsedMilliseconds);
    Console.WriteLine(secondCert.AccessToken == firstCert.AccessToken);
}
