namespace FinnasAPI.Services;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using FinnasAPI.DAL;
using FinnasAPI.Models;
using Microsoft.IdentityModel.Tokens;

public class AuthService : IAuthService
{
    private readonly IUserRepository _userRepository;
    private readonly IConfiguration _configuration;

    public AuthService(IUserRepository userRepository, IConfiguration configuration)
    {
        _userRepository = userRepository;
        _configuration = configuration;
    }

    public async Task<(bool Success, string Message, AuthResponse? Response)> RegisterAsync(RegisterRequest request)
    {
        var passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

        var (userId, message) = await _userRepository.CreateUserAsync(request.Name, request.Email, passwordHash);

        if (userId <= 0)
            return (false, message, null);

        var accessToken = GenerateAccessToken(userId, request.Email, request.Name);
        var refreshToken = GenerateRefreshToken();
        var expiresAt = DateTime.UtcNow.AddDays(7);

        await _userRepository.SaveRefreshTokenAsync(userId, refreshToken, expiresAt);

        return (true, "Account created successfully", new AuthResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            Name = request.Name,
            Email = request.Email
        });
    }

    public async Task<(bool Success, string Message, AuthResponse? Response)> LoginAsync(LoginRequest request)
    {
        var user = await _userRepository.GetUserByEmailAsync(request.Email);

        if (user is null || !user.IsActive)
            return (false, "Invalid credentials", null);

        if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            return (false, "Invalid credentials", null);

        var accessToken = GenerateAccessToken(user.Id, user.Email, user.Name);
        var refreshToken = GenerateRefreshToken();
        var expiresAt = DateTime.UtcNow.AddDays(7);

        await _userRepository.SaveRefreshTokenAsync(user.Id, refreshToken, expiresAt);

        return (true, "Login successful", new AuthResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            Name = user.Name,
            Email = user.Email
        });
    }

    public async Task<(bool Success, AuthResponse? Response)> RefreshTokenAsync(string refreshToken)
    {
        var result = await _userRepository.ValidateRefreshTokenAsync(refreshToken);

        if (result is null)
            return (false, null);

        var (userId, email, name) = result.Value;

        var newAccessToken = GenerateAccessToken(userId, email, name);
        var newRefreshToken = GenerateRefreshToken();
        var expiresAt = DateTime.UtcNow.AddDays(7);

        await _userRepository.SaveRefreshTokenAsync(userId, newRefreshToken, expiresAt);

        return (true, new AuthResponse
        {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken,
            Name = name,
            Email = email
        });
    }

    private string GenerateAccessToken(int userId, string email, string name)
    {
        var jwtSettings = _configuration.GetSection("JwtSettings");
        var secretKey = jwtSettings["SecretKey"]!;
        var issuer = jwtSettings["Issuer"]!;
        var audience = jwtSettings["Audience"]!;
        var expiresMin = int.Parse(jwtSettings["ExpiresInMinutes"]!);

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub,   userId.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, email),
            new Claim(JwtRegisteredClaimNames.Name,  name),
            new Claim(JwtRegisteredClaimNames.Jti,   Guid.NewGuid().ToString())
        };

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(expiresMin),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string GenerateRefreshToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(64);
        return Convert.ToBase64String(bytes);
    }
}