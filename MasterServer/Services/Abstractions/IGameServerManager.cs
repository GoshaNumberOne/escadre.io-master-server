using MasterServer.DTOs.Server; 
using System.Collections.Generic;
using System.Threading.Tasks;

namespace MasterServer.Services.Abstractions
{
    public record GameServerRegistrationData(
         string Id,
         string Name,
         string IpAddress,
         int Port,
         string Region,
         int MaxPlayers
    );

    public interface IGameServerManager
    {
        Task RegisterOrUpdateServerAsync(GameServerRegistrationData serverData);
        Task UpdateServerStatusAsync(string serverId, int currentPlayers, string status);
        Task UnregisterServerAsync(string serverId);
        Task<IEnumerable<GameServerInfoDto>> GetAvailableServersAsync(string? regionFilter = null);
        Task<GameServerInfoDto?> GetServerByIdAsync(string serverId);
    }
}