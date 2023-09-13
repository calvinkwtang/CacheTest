using Microsoft.Identity.Web;
using Microsoft.Identity.Client;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Caching.Memory;
using System.Diagnostics;
using Microsoft.Identity.Web.TokenCacheProviders.InMemory;

var audience = "<audience>";
var tenant = "<tenant>";
var appId = "<appId>";
var tokenFormat = "<tokenformat>";
var authority = new Uri(string.Format(tokenFormat, tenant));
var secret = "<secret>";

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
