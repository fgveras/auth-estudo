namespace FinnasAPI.DAL;

using FinnasAPI.Models;

public interface IUserRepository
{
    Task<(int UserId, string Message)> CreateUserAsync(string name, string email, string passwordHash);
    Task<User?> GetUserByEmailAsync(string email);
    Task<User?> GetUserByIdAsync(int id);
    Task SaveRefreshTokenAsync(int userId, string token, DateTime expiresAt);
    Task<(int UserId, string Email, string Name)?> ValidateRefreshTokenAsync(string token);
}