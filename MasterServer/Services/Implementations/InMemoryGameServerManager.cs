using MasterServer.DTOs.Server;
using MasterServer.Services.Abstractions;
using System.Collections.Concurrent; 

namespace MasterServer.Services.Implementations
{
    public class InMemoryGameServerManager : IGameServerManager
    {
        private readonly ConcurrentDictionary<string, GameServerInfoDto> _servers =
            new ConcurrentDictionary<string, GameServerInfoDto>();
        private readonly ConcurrentDictionary<string, DateTime> _serverHeartbeats =
            new ConcurrentDictionary<string, DateTime>();
        private readonly TimeSpan _heartbeatTimeout = TimeSpan.FromMinutes(1); 

        public Task RegisterOrUpdateServerAsync(GameServerRegistrationData serverData)
        {
            var serverInfo = new GameServerInfoDto
            {
                Id = serverData.Id,
                Name = serverData.Name,
                IpAddress = serverData.IpAddress,
                Port = serverData.Port,
                Region = serverData.Region,
                MaxPlayers = serverData.MaxPlayers,
                CurrentPlayers = 0, 
                Status = "Initializing" 
            };

            _servers.AddOrUpdate(serverInfo.Id, serverInfo, (key, existingVal) =>
            {
                serverInfo.CurrentPlayers = existingVal.CurrentPlayers;
                serverInfo.Status = existingVal.Status;
                return serverInfo;
            });

            _serverHeartbeats.AddOrUpdate(serverInfo.Id, DateTime.UtcNow, (k, v) => DateTime.UtcNow);
            return Task.CompletedTask;
        }

        public Task UpdateServerStatusAsync(string serverId, int currentPlayers, string status)
        {
            if (_servers.TryGetValue(serverId, out var serverInfo))
            {
                serverInfo.CurrentPlayers = currentPlayers;
                serverInfo.Status = status;
                _servers.TryUpdate(serverId, serverInfo, serverInfo);

                _serverHeartbeats.AddOrUpdate(serverId, DateTime.UtcNow, (k, v) => DateTime.UtcNow);
            }

            return Task.CompletedTask;
        }

        public Task UnregisterServerAsync(string serverId)
        {
            _servers.TryRemove(serverId, out _);
            _serverHeartbeats.TryRemove(serverId, out _);

            return Task.CompletedTask;
        }

        public Task<IEnumerable<GameServerInfoDto>> GetAvailableServersAsync(string? regionFilter = null)
        {
            CleanupExpiredServers();

            IEnumerable<GameServerInfoDto> query = _servers.Values;

            if (!string.IsNullOrEmpty(regionFilter))
            {
                query = query.Where(s => s.Region != null && s.Region.Equals(regionFilter, StringComparison.OrdinalIgnoreCase));
            }

            return Task.FromResult(query.ToList().AsEnumerable());
        }

        public Task<GameServerInfoDto?> GetServerByIdAsync(string serverId)
        {
            _servers.TryGetValue(serverId, out var serverInfo);
            return Task.FromResult(serverInfo);
        }

        private void CleanupExpiredServers()
        {
            var now = DateTime.UtcNow;
            var expiredServerIds = _serverHeartbeats
                .Where(kvp => (now - kvp.Value) > _heartbeatTimeout)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var serverId in expiredServerIds)
            {
                 if (_serverHeartbeats.TryRemove(serverId, out _))
                 {
                      _servers.TryRemove(serverId, out _);
                 }
            }
        }
    }
}