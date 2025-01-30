using BaseLibrary.DTOs;
using BaseLibrary.Entities;
using BaseLibrary.Responses;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repositories.Contracts;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ServerLibrary.Repositories.Implementation;

public sealed class UserAccountRepository(IOptions<JwtSection> config, AppDbContext appDbContext)
    : IUserAccountRepository
{
    public async Task<GeneralResponse> CreateAsync(Register user)
    {
        if (user is null)
            return new GeneralResponse(false, "User is required.");

        var checkUser = await FindUserByEmailAsync(user.Email!);
        if (checkUser is not null)
            return new GeneralResponse(false, "User is already registered.");

        // Save user
        var applicationUser = await AddToDatabaseAsync(new ApplicationUser()
        {
            Fullname = user.Fullname,
            Email = user.Email,
            Password = BCrypt.Net.BCrypt.HashPassword(user.Password),
        });

        // Check, create and assign role
        var checkAdminRole = await appDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Name!.Equals(Constants.Admin));
        if (checkAdminRole is null)
        {
            var createAdminRole = await AddToDatabaseAsync(new SystemRole() { Name = Constants.Admin });
            await AddToDatabaseAsync(new UserRole() { RoleId = createAdminRole.Id, UserId = applicationUser.Id });
            return new GeneralResponse(true, "Admin account created.");
        }

        var checkUserRole = await appDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Name!.Equals(Constants.User));
        if (checkUserRole is null)
        {
            var createUserRole = await AddToDatabaseAsync(new SystemRole() { Name = Constants.User });
            await AddToDatabaseAsync(new UserRole() { RoleId = createUserRole.Id, UserId = applicationUser.Id });
            return new GeneralResponse(true, "User account created.");
        }

        await AddToDatabaseAsync(new UserRole() { RoleId = checkUserRole.Id, UserId = applicationUser.Id });
        return new GeneralResponse(true, "User account created.");
    }

    public async Task<LoginResponse> SignInAsync(Login user)
    {
        if (user is null)
            return new LoginResponse(false, "User is required.");

        var applicationUser = await FindUserByEmailAsync(user.Email!);
        if (applicationUser is null)
            return new LoginResponse(false, "User not found.");

        // Verify password
        if (!BCrypt.Net.BCrypt.Verify(user.Password, applicationUser.Password))
            return new LoginResponse(false, "User credentials are invalid.");

        var getUserRole = await FindUserRoleAsync(applicationUser.Id);
        if (getUserRole is null)
            return new LoginResponse(false, "User role not found.");

        var getRoleName = await FindSystemRoleAsync(getUserRole.RoleId);
        if (getRoleName is null)
            return new LoginResponse(false, "Role not found.");

        var jwtToken = GenerateToken(applicationUser, getRoleName!.Name!);
        var refreshToken = GenerateRefreshToken();

        // Save the Refresh token to the database
        var findUser = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.UserId == applicationUser.Id);
        if (findUser is not null)
        {
            findUser.Token = refreshToken;
            await appDbContext.SaveChangesAsync();
        }
        else
        {
            await AddToDatabaseAsync(new RefreshTokenInfo() { UserId = applicationUser.Id, Token = refreshToken });
        }

        return new LoginResponse(true, "User login successfully.", jwtToken, refreshToken);
    }

    public async Task<LoginResponse> RefreshTokenAsync(RefreshToken token)
    {
        if (token is null)
            return new LoginResponse(false, "Refresh token is required.");

        var findToken = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.Token!.Equals(token.Token));
        if (findToken is null)
            return new LoginResponse(false, "Refresh token not found.");

        var applicationUser = await appDbContext.ApplicationUsers.FirstOrDefaultAsync(_ => _.Id == findToken.UserId);
        if (applicationUser is null)
            return new LoginResponse(false, "User not found. Refresh token could not be generated.");

        var getUserRole = await FindUserRoleAsync(applicationUser.Id);
        var getRoleName = await FindSystemRoleAsync(getUserRole!.RoleId);

        var jwtToken = GenerateToken(applicationUser, getRoleName!.Name!);
        var refreshToken = GenerateRefreshToken();

        var updateRefreshToken = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.UserId == applicationUser.Id);
        if (updateRefreshToken is null)
            return new LoginResponse(false, "Refresh token could not be generated because user has not signed in.");

        updateRefreshToken.Token = refreshToken;
        await appDbContext.SaveChangesAsync();

        return new LoginResponse(true, "Token refreshed successfully.", jwtToken, refreshToken);
    }

    private async Task<ApplicationUser?> FindUserByEmailAsync(string email)
        => await appDbContext.ApplicationUsers.FirstOrDefaultAsync(_ => _.Email!.ToLower().Equals(email!.ToLower()));

    private async Task<UserRole?> FindUserRoleAsync(int userId)
        => await appDbContext.UserRoles.FirstOrDefaultAsync(_ => _.UserId == userId);

    private async Task<SystemRole?> FindSystemRoleAsync(int roleId)
        => await appDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Id == roleId);

    private async Task<T> AddToDatabaseAsync<T>(T model)
    {
        var result = appDbContext.Add(model!);
        await appDbContext.SaveChangesAsync();
        return (T)result.Entity;
    }

    private string GenerateToken(ApplicationUser user, string role)
    {
        var jwtSection = config.Value;

        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSection.Key!));

        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var userClaims = new[]
        {
            GenerateClaim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            GenerateClaim(ClaimTypes.Name, user.Fullname!),
            GenerateClaim(ClaimTypes.Email, user.Email!),
            GenerateClaim(ClaimTypes.Role, role!),
        };

        var token = new JwtSecurityToken(
            issuer: jwtSection.Issuer,
            audience: jwtSection.Audience,
            claims: userClaims,
            expires: DateTime.Now.AddDays(1),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static Claim GenerateClaim(string type, string value)
        => new(type, value);

    private static string GenerateRefreshToken()
        => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
}
