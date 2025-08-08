using Microsoft.AspNetCore.Mvc;
using UserAuthApi.Models;
using UserAuthApi.Services;

namespace UserAuthApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserService _users;
    private readonly TokenService _tokens;

    public AuthController(UserService users, TokenService tokens)
    {
        _users = users;
        _tokens = tokens;
    }

    [HttpPost("register")]
    public IActionResult Register(UserDto request)
    {
        var created = _users.Register(request.Username, request.Password);
        if (!created)
        {
            return BadRequest("User already exists");
        }
        return Ok();
    }

    [HttpPost("login")]
    public IActionResult Login(UserDto request)
    {
        var user = _users.Authenticate(request.Username, request.Password);
        if (user is null)
        {
            return Unauthorized();
        }
        var token = _tokens.CreateToken(user);
        return Ok(new { token });
    }
}

public record UserDto(string Username, string Password);
