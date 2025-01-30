using BaseLibrary.DTOs;
using BaseLibrary.Responses;
using ClientLibrary.Helpers;
using ClientLibrary.Services.Contracts;
using System.Net.Http.Json;

namespace ClientLibrary.Services.Implementation;

public sealed class UserAccountService(GetHttpClient getHttpClient)
    : IUserAccountService
{
    public const string AuthUrl = "api/authentication";

    public async Task<GeneralResponse> CreateAsync(Register user)
    {
        var httpClient = getHttpClient.GetPublicHttpClient();
        var result = await httpClient.PostAsJsonAsync($"{AuthUrl}/register", user);

        if (!result.IsSuccessStatusCode)
            return new GeneralResponse(false, "Error ocurred.");

        var response = await result.Content.ReadFromJsonAsync<GeneralResponse>();
        return response!;
    }

    public async Task<LoginResponse> SignInAsync(Login user)
    {
        var httpClient = getHttpClient.GetPublicHttpClient();
        var result = await httpClient.PostAsJsonAsync($"{AuthUrl}/login", user);

        if (!result.IsSuccessStatusCode)
            return new LoginResponse(false, "Error ocurred.");

        var response = await result.Content.ReadFromJsonAsync<LoginResponse>();
        return response!;
    }

    public async Task<LoginResponse> RefreshTokenAsync(RefreshToken token)
    {
        var httpClient = getHttpClient.GetPublicHttpClient();
        var result = await httpClient.PostAsJsonAsync($"{AuthUrl}/refresh-token", token);

        if (!result.IsSuccessStatusCode)
            return new LoginResponse(false, "Error ocurred.");

        var response = await result.Content.ReadFromJsonAsync<LoginResponse>();
        return response!;
    }

    public async Task<WeatherForecast[]> GetWeatherForecast()
    {
        var httpClient = await getHttpClient.GetPrivateHttpClient();
        var result = await httpClient.GetFromJsonAsync<WeatherForecast[]>("api/weatherforecast");
        return result!;
    }
}
