using System;
using System.ComponentModel.DataAnnotations;       
using System.ComponentModel.DataAnnotations.Schema; 

namespace MasterServer.Data.Entities
{
    public class PlayerStat
    {
        [Key]
        [ForeignKey("User")] 
        public string UserId { get; set; } = null!; 

        public int Kills { get; set; } = 0; 
        public int Deaths { get; set; } = 0; 
        public TimeSpan PlayTime { get; set; } = TimeSpan.Zero;

        public virtual User User { get; set; } = null!;
    }
}