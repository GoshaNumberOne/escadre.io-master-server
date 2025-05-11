using Microsoft.AspNetCore.Identity; // Добавить этот using

namespace MasterServer.Data.Entities
{
    // Наследуемся от IdentityUser
    public class User : IdentityUser
    {
        // IdentityUser уже содержит:
        // Id (string), UserName, NormalizedUserName, Email, NormalizedEmail,
        // EmailConfirmed, PasswordHash, SecurityStamp, ConcurrencyStamp,
        // PhoneNumber, PhoneNumberConfirmed, TwoFactorEnabled, LockoutEnd,
        // LockoutEnabled, AccessFailedCount

        // Добавляем твои кастомные поля
        public required string Nickname { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        // RefreshTokens и PlayerStat остаются как есть,
        // но FK в PlayerStat будет ссылаться на Id из IdentityUser
        public virtual ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
        public virtual PlayerStat? Stats { get; set; }
    }
}