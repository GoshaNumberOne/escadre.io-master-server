// MasterServer/Services/Implementations/UserService.cs
using MasterServer.Data;
using MasterServer.Data.Entities;
using MasterServer.Services.Abstractions;
using Microsoft.AspNetCore.Identity; // Для UserManager, если понадобится
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;

namespace MasterServer.Services.Implementations
{
    public class UserService : IUserService
    {
        private readonly AppDbContext _context;
        private readonly UserManager<User> _userManager; // Можно внедрить, если нужны специфичные операции

        public UserService(AppDbContext context, UserManager<User> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        // Эти методы теперь дублируют UserManager, но могут быть оставлены для совместимости или кастомной логики

        public async Task<User?> FindUserByIdentifierAsync(string identifier)
        {
            var user = await _userManager.FindByEmailAsync(identifier);
            if (user == null)
            {
                user = await _userManager.FindByNameAsync(identifier); // UserName может быть Nickname
            }
            return user;
        }

         public async Task<User?> FindUserByIdAsync(string userId)
        {
            return await _userManager.FindByIdAsync(userId);
        }

        // CreateUserAsync теперь лучше делать через UserManager в AuthService
        // для корректной обработки пароля и других полей Identity
        public async Task<string?> CreateUserAsync(string email, string hashedPassword, string nickname)
        {
            // ЭТОТ МЕТОД ЛУЧШЕ НЕ ИСПОЛЬЗОВАТЬ С IDENTITY НАПРЯМУЮ,
            // так как UserManager.CreateAsync делает больше работы (хеширование, нормализация и т.д.)
            // Оставлен для примера, но регистрация должна идти через AuthService -> UserManager
            var user = new User { Email = email, UserName = email, Nickname = nickname, PasswordHash = hashedPassword };
            _context.Users.Add(user);
            try
            {
                await _context.SaveChangesAsync();
                return user.Id;
            }
            catch { return null; }
        }

        public async Task<bool> CheckIfUserExistsAsync(string identifier)
        {
            var user = await FindUserByIdentifierAsync(identifier);
            return user != null;
        }

        public async Task<string?> GetPasswordHashAsync(string identifier)
        {
            var user = await FindUserByIdentifierAsync(identifier);
            return user?.PasswordHash; // PasswordHash из IdentityUser
        }
    }
}