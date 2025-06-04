namespace MasterServer.DTOs.Server
{
    public class GameServerInfoDto
    {
        public required string Id { get; set; }
        public required string Name { get; set; }
        public required string IpAddress { get; set; }
        public required int Port { get; set; }
        public string? Region { get; set; }
        public required int CurrentPlayers { get; set; }
        public required int MaxPlayers { get; set; }
        public required string Status { get; set; }
    }
}