// MasterServer/DTOs/User/PlayerStatsDto.cs (или подобное место)
namespace MasterServer.DTOs
{
    public class PlayerStatsDto
    {
        public required string Nickname { get; set; }
        public int Kills { get; set; }
        public int Deaths { get; set; }
        public string PlayTime { get; set; } // Будем форматировать TimeSpan в строку
        public float KDRatio { get; set; }
        // Можно добавить другие поля, если нужно
    }
}