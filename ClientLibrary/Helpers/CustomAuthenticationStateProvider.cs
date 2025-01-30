using BaseLibrary.DTOs;
using Microsoft.AspNetCore.Components.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace ClientLibrary.Helpers;

public class CustomAuthenticationStateProvider(LocalStorageService localStorageService)
    : AuthenticationStateProvider
{
    private readonly ClaimsPrincipal anonymous = new(new ClaimsIdentity());

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var stringToken = await localStorageService.GetToken();

        if (string.IsNullOrEmpty(stringToken))
            return await Task.FromResult(new AuthenticationState(anonymous));

        var deserializeToken = Serializations.Deserialize<UserSession>(stringToken);
        if (deserializeToken is null)
            return await Task.FromResult(new AuthenticationState(anonymous));

        var getUserClaims = DecryptToken(deserializeToken.Token!);
        if (getUserClaims is null)
            return await Task.FromResult(new AuthenticationState(anonymous));

        var claimsPrincipal = SetClaimPrincipal(getUserClaims);
        return await Task.FromResult(new AuthenticationState(claimsPrincipal));
    }

    public async Task UpdateAuthenticationState(UserSession userSession)
    {
        var claimsPrincipal = new ClaimsPrincipal();

        if (userSession.Token is not null ||
            userSession.RefreshToken is not null)
        {
            var serializeSession = Serializations.Serialize(userSession);
            await localStorageService.SetToken(serializeSession);
            var getUserClaims = DecryptToken(userSession.Token!);
            claimsPrincipal = SetClaimPrincipal(getUserClaims);
        }
        else
        {
            await localStorageService.RemoveToken();
        }

        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
    }

    private static CustomUserClaims DecryptToken(string jwtToken)
    {
        if (string.IsNullOrEmpty(jwtToken))
            return new CustomUserClaims();

        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(jwtToken);
        var userId = GetTokenClaim(token, ClaimTypes.NameIdentifier);
        var name = GetTokenClaim(token, ClaimTypes.Name);
        var email = GetTokenClaim(token, ClaimTypes.Email);
        var role = GetTokenClaim(token, ClaimTypes.Role);

        return new CustomUserClaims(userId!.ValueType!, name!.Value, email!.Value, role!.Value);
    }

    private static Claim? GetTokenClaim(JwtSecurityToken token, string type)
        => token.Claims.FirstOrDefault(_ => _.Type == type);

    private static ClaimsPrincipal SetClaimPrincipal(CustomUserClaims claims)
    {
        if (claims.Email is null)
            return new ClaimsPrincipal();

        return new ClaimsPrincipal(new ClaimsIdentity(
        [
            new(ClaimTypes.NameIdentifier, claims.Id!),
            new(ClaimTypes.Name, claims.Name!),
            new(ClaimTypes.Email, claims.Email!),
            new(ClaimTypes.Role, claims.Role!),
        ], "JwtAuth"));
    }
}
