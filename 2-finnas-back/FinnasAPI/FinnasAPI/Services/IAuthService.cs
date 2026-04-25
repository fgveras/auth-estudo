namespace FinnasAPI.Services;

using FinnasAPI.Models;

public interface IAuthService
{
    Task<(bool Success, string Message, AuthResponse? Response)> RegisterAsync(RegisterRequest request);
    Task<(bool Success, string Message, AuthResponse? Response)> LoginAsync(LoginRequest request);
    Task<(bool Success, AuthResponse? Response)> RefreshTokenAsync(string refreshToken);
}