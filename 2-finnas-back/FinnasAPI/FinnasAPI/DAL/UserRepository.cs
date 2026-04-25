namespace FinnasAPI.DAL;

using FinnasAPI.Models;
using Microsoft.Data.SqlClient;
using System.Data;

public class UserRepository : IUserRepository
{
    private readonly string _connectionString;

    public UserRepository(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("DefaultConnection")
            ?? throw new InvalidOperationException("Connection string not found.");
    }

    private SqlConnection CreateConnection() => new SqlConnection(_connectionString);

    public async Task<(int UserId, string Message)> CreateUserAsync(string name, string email, string passwordHash)
    {
        using var conn = CreateConnection();
        using var cmd = new SqlCommand("sp_CreateUser", conn) { CommandType = CommandType.StoredProcedure };

        cmd.Parameters.AddWithValue("@Name", name);
        cmd.Parameters.AddWithValue("@Email", email);
        cmd.Parameters.AddWithValue("@PasswordHash", passwordHash);

        await conn.OpenAsync();
        using var reader = await cmd.ExecuteReaderAsync();

        if (await reader.ReadAsync())
        {
            return (
                reader.GetInt32(reader.GetOrdinal("UserId")),
                reader.GetString(reader.GetOrdinal("Message"))
            );
        }

        return (-1, "Unknown error");
    }

    public async Task<User?> GetUserByEmailAsync(string email)
    {
        using var conn = CreateConnection();
        using var cmd = new SqlCommand("sp_GetUserByEmail", conn) { CommandType = CommandType.StoredProcedure };

        cmd.Parameters.AddWithValue("@Email", email);

        await conn.OpenAsync();
        using var reader = await cmd.ExecuteReaderAsync();

        if (await reader.ReadAsync())
        {
            return new User
            {
                Id = reader.GetInt32(reader.GetOrdinal("Id")),
                Name = reader.GetString(reader.GetOrdinal("Name")),
                Email = reader.GetString(reader.GetOrdinal("Email")),
                PasswordHash = reader.GetString(reader.GetOrdinal("PasswordHash")),
                IsActive = reader.GetBoolean(reader.GetOrdinal("IsActive"))
            };
        }

        return null;
    }

    public async Task<User?> GetUserByIdAsync(int id)
    {
        using var conn = CreateConnection();
        using var cmd = new SqlCommand("sp_GetUserById", conn) { CommandType = CommandType.StoredProcedure };

        cmd.Parameters.AddWithValue("@Id", id);

        await conn.OpenAsync();
        using var reader = await cmd.ExecuteReaderAsync();

        if (await reader.ReadAsync())
        {
            return new User
            {
                Id = reader.GetInt32(reader.GetOrdinal("Id")),
                Name = reader.GetString(reader.GetOrdinal("Name")),
                Email = reader.GetString(reader.GetOrdinal("Email")),
                IsActive = reader.GetBoolean(reader.GetOrdinal("IsActive")),
                CreatedAt = reader.GetDateTime(reader.GetOrdinal("CreatedAt"))
            };
        }

        return null;
    }

    public async Task SaveRefreshTokenAsync(int userId, string token, DateTime expiresAt)
    {
        using var conn = CreateConnection();
        using var cmd = new SqlCommand("sp_SaveRefreshToken", conn) { CommandType = CommandType.StoredProcedure };

        cmd.Parameters.AddWithValue("@UserId", userId);
        cmd.Parameters.AddWithValue("@Token", token);
        cmd.Parameters.AddWithValue("@ExpiresAt", expiresAt);

        await conn.OpenAsync();
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<(int UserId, string Email, string Name)?> ValidateRefreshTokenAsync(string token)
    {
        using var conn = CreateConnection();
        using var cmd = new SqlCommand("sp_ValidateRefreshToken", conn) { CommandType = CommandType.StoredProcedure };

        cmd.Parameters.AddWithValue("@Token", token);

        await conn.OpenAsync();
        using var reader = await cmd.ExecuteReaderAsync();

        if (await reader.ReadAsync())
        {
            return (
                reader.GetInt32(reader.GetOrdinal("UserId")),
                reader.GetString(reader.GetOrdinal("Email")),
                reader.GetString(reader.GetOrdinal("Name"))
            );
        }

        return null;
    }
}