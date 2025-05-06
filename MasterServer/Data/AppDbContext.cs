using Microsoft.EntityFrameworkCore;
using MasterServer.Data.Entities;

namespace MasterServer.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
        public DbSet<User> Users { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<PlayerStat> PlayerStats { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<User>(entity =>
            {
                entity.HasIndex(u => u.Email).IsUnique();
                entity.HasIndex(u => u.Nickname);
            });

             modelBuilder.Entity<RefreshToken>(entity =>
            {
                entity.HasIndex(rt => rt.Token).IsUnique();
                entity.HasOne(rt => rt.User)
                      .WithMany(u => u.RefreshTokens)
                      .HasForeignKey(rt => rt.UserId);
            });

            modelBuilder.Entity<User>()
                .HasOne(u => u.Stats)
                .WithOne(ps => ps.User)
                .HasForeignKey<PlayerStat>(ps => ps.UserId);

            modelBuilder.Entity<PlayerStat>()
                .Property(ps => ps.PlayTime)
                .HasColumnType("interval");
        }
    }
}