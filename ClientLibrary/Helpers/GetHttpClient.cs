using BaseLibrary.DTOs;
using System.Net.Http.Headers;

namespace ClientLibrary.Helpers;

public class GetHttpClient(IHttpClientFactory httpClientFactory, LocalStorageService localStorageService)
{
    private const string HeaderKey = "Authorization";

    public async Task<HttpClient> GetPrivateHttpClient()
    {
        var client = httpClientFactory.CreateClient("SystemApiClient");
        var stringToken = await localStorageService.GetToken();

        if (string.IsNullOrEmpty(stringToken))
            return client;

        var deserializeToken = Serializations.Deserialize<UserSession>(stringToken);
        if (deserializeToken is null)
            return client;

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", deserializeToken.Token);
        return client;
    }

    public HttpClient GetPublicHttpClient()
    {
        var client = httpClientFactory.CreateClient("SystemApiClient");
        client.DefaultRequestHeaders.Remove(HeaderKey);
        return client;
    }
}
