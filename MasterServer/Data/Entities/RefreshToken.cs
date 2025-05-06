namespace MasterServer.Data.Entities
{
     public class RefreshToken
     {
         public int Id { get; set; }
         public required string Token { get; set; }
         public DateTime ExpiryDate { get; set; }
         public bool IsRevoked { get; set; } = false;
         public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

         public required string UserId { get; set; }
         public virtual User User { get; set; } = null!;
     }
}