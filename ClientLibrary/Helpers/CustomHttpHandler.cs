using BaseLibrary.DTOs;
using ClientLibrary.Services.Contracts;
using System.Net.Http.Headers;

namespace ClientLibrary.Helpers;

public sealed class CustomHttpHandler(LocalStorageService localStorageService, IUserAccountService accountService)
    : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        bool loginUrl = request.RequestUri!.AbsoluteUri.Contains("login");
        bool registerUrl = request.RequestUri!.AbsoluteUri.Contains("register");
        bool refreshTokenUrl = request.RequestUri!.AbsoluteUri.Contains("refresh-token");

        if (loginUrl || registerUrl || refreshTokenUrl)
            return await base.SendAsync(request, cancellationToken);

        var result = await base.SendAsync(request, cancellationToken);
        if (result.StatusCode is System.Net.HttpStatusCode.Unauthorized)
        {
            // Get Token from LocalStorage
            var stringToken = await localStorageService.GetToken();
            if (stringToken is null)
                return result;

            // Check if the header contains Token
            var token = string.Empty;
            try { token = request.Headers.Authorization!.Parameter!; }
            catch (Exception) { }

            // Deserialize Token
            var deserializeToken = Serializations.Deserialize<UserSession>(stringToken);

            if (deserializeToken is null)
                return result;

            if (string.IsNullOrEmpty(token))
            {
                // Add Token to the header
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", deserializeToken.Token);
                return await base.SendAsync(request, cancellationToken);
            }

            // Call for Refresh Token
            var newJwtToken = await GetNewTokenByRefreshToken(deserializeToken.RefreshToken!);
            if (string.IsNullOrEmpty(newJwtToken))
                return result;

            // Add new Token to the header
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", newJwtToken);
            return await base.SendAsync(request, cancellationToken);
        }

        return result;
    }

    private async Task<string> GetNewTokenByRefreshToken(string refreshToken)
    {
        var result = await accountService.RefreshTokenAsync(new RefreshToken { Token = refreshToken });

        var serializedToken = Serializations.Serialize(new UserSession() { Token = result.Token, RefreshToken = result.RefreshToken });
        await localStorageService.SetToken(serializedToken);

        return result.Token;
    }
}
