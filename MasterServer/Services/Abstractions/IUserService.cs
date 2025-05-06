using MasterServer.Data.Entities;

namespace MasterServer.Services.Abstractions
{
    public record UserDetails(string UserId, string Email, string Nickname);
    public interface IUserService
    {
        Task<User?> FindUserByIdentifierAsync(string identifier); 
        Task<User?> FindUserByIdAsync(string userId);
        Task<string?> CreateUserAsync(string email, string hashedPassword, string nickname);
        Task<bool> CheckIfUserExistsAsync(string identifier);
        Task<string?> GetPasswordHashAsync(string identifier);
    }
}