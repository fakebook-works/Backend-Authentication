namespace fakebookAuth;

using System;
using System.Threading.Tasks;
using Npgsql;
using Dapper;

public class User {
    public long user_id { get; set; }
    public string email { get; set; }
    public string phone { get; set; }
    public string username { get; set; }
    public string display_name { get; set; }
    public short status { get; set; }
    public DateTime created_at { get; set; }
    public DateTime updated_at { get; set; }
}

public class IdentityService {
    private readonly string _connectionString;

    public IdentityService(string connectionString) {
        _connectionString = connectionString;
    }
    public async Task<User> GetUserByIdAsync(long userId) {
        using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync();

        var sql = @"
                SELECT user_id, email, phone, username, display_name, status, created_at, updated_at 
                FROM fb.id_user 
                WHERE user_id = @UserId";

        return await connection.QuerySingleOrDefaultAsync<User>(sql, new { UserId = userId });
    }
    public async Task<bool> CreateUserAsync(User newUser) {
        using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync();

        var sql = @"
                INSERT INTO fb.id_user (user_id, email, phone, username, display_name, status)
                VALUES (@user_id, @email, @phone, @username, @display_name, @status)";

        var rowsAffected = await connection.ExecuteAsync(sql, newUser);
        return rowsAffected > 0;
    }
}