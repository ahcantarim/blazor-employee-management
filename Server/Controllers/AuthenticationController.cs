﻿using BaseLibrary.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ServerLibrary.Repositories.Contracts;

namespace Server.Controllers;

[Route("api/[controller]")]
[ApiController]
[AllowAnonymous]
public class AuthenticationController(IUserAccountRepository userAccountRepository)
    : ControllerBase
{
    [HttpPost("register")]
    public async Task<IActionResult> CreateAsync(Register user)
    {
        if (user is null)
            return BadRequest("User is required.");

        var result = await userAccountRepository.CreateAsync(user);
        return Ok(result);
    }

    [HttpPost("login")]
    public async Task<IActionResult> SignInAsync(Login user)
    {
        if (user is null)
            return BadRequest("User is required.");

        var result = await userAccountRepository.SignInAsync(user);
        return Ok(result);
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshTokenAsync(RefreshToken token)
    {
        if (token is null)
            return BadRequest("Refresh token is required.");

        var result = await userAccountRepository.RefreshTokenAsync(token);
        return Ok(result);
    }
}
