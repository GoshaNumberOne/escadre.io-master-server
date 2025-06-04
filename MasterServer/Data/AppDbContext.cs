using Microsoft.AspNetCore.Identity.EntityFrameworkCore; // Добавить этот using
using Microsoft.EntityFrameworkCore;
using MasterServer.Data.Entities;

namespace MasterServer.Data
{
    // Наследуемся от IdentityDbContext<User>
    public class AppDbContext : IdentityDbContext<User> 
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        // DbSet<User> Users уже будет предоставлен IdentityDbContext
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<PlayerStat> PlayerStats { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder); // ОЧЕНЬ ВАЖНО вызвать base.OnModelCreating!

            // Здесь твои кастомные конфигурации для User (если нужны, сверх Identity),
            // RefreshToken, PlayerStat и их связей.
            // Identity сам настроит таблицы AspNetUsers, AspNetRoles и т.д.

            builder.Entity<User>(entity =>
            {
                // Доп. настройки для User, если нужно (например, индекс на Nickname)
                entity.HasIndex(u => u.Nickname);
                // Email уже будет уникальным по умолчанию из IdentityUser
            });

            // Конфигурация RefreshToken и PlayerStat остается похожей,
            // только FK в PlayerStat будет на User.Id из IdentityUser
            builder.Entity<RefreshToken>(entity =>
            {
                entity.HasIndex(rt => rt.Token).IsUnique();
                entity.HasOne(rt => rt.User)
                      .WithMany(u => u.RefreshTokens) // У IdentityUser нет такого свойства по умолчанию, его добавили мы
                      .HasForeignKey(rt => rt.UserId);
            });

            builder.Entity<User>()
                .HasOne(u => u.Stats)
                .WithOne(ps => ps.User)
                .HasForeignKey<PlayerStat>(ps => ps.UserId);

            builder.Entity<PlayerStat>()
                .Property(ps => ps.PlayTime)
                .HasColumnType("interval");
        }
    }
}