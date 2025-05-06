using MasterServer.Data;
using MasterServer.Data.Entities; 
using MasterServer.Services.Abstractions;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;

namespace MasterServer.Services.Implementations
{
    public class UserService : IUserService 
    {
        private readonly AppDbContext _context;

        public UserService(AppDbContext context)
        {
            _context = context;
        }

        public async Task<User?> FindUserByIdentifierAsync(string identifier)
        {
            identifier = identifier.ToLowerInvariant();
            return await _context.Users
                .FirstOrDefaultAsync(u => u.Email.ToLower() == identifier || u.Nickname.ToLower() == identifier);
        }

         public async Task<User?> FindUserByIdAsync(string userId)
        {
            return await _context.Users.FindAsync(userId);
        }

        public async Task<string?> CreateUserAsync(string email, string hashedPassword, string nickname)
        {
            var user = new User
            {
                Email = email,
                Nickname = nickname,
                PasswordHash = hashedPassword
            };

            _context.Users.Add(user);
            try
            {
                await _context.SaveChangesAsync();
                return user.Id;
            }
            catch (DbUpdateException ex)
            {
                // TODO: залогировать ошибку
                Console.WriteLine($"Error creating user: {ex.Message}"); 
                return null;
            }
        }

        public async Task<bool> CheckIfUserExistsAsync(string identifier)
        {
            identifier = identifier.ToLowerInvariant();
            return await _context.Users
                .AnyAsync(u => u.Email.ToLower() == identifier || u.Nickname.ToLower() == identifier);
        }

        public async Task<string?> GetPasswordHashAsync(string identifier)
        {
            identifier = identifier.ToLowerInvariant();
            var passwordHash = await _context.Users
                         .Where(u => u.Email.ToLower() == identifier || u.Nickname.ToLower() == identifier)
                         .Select(u => u.PasswordHash) 
                         .FirstOrDefaultAsync(); 
            return passwordHash;
        }
    }
}