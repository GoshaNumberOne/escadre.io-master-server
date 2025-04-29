// Hubs/MasterHub.cs
using Microsoft.AspNetCore.SignalR;
using System.Threading.Tasks; // Для использования Task

namespace MasterServer.Hubs // Убедись, что namespace правильный
{
    public class MasterHub : Hub
    {
        // --- Метод, который КЛИЕНТ может вызвать на СЕРВЕРЕ ---
        // Например, клиент отправляет сообщение в общий чат или запрос на поиск игры
        public async Task SendMessageToAll(string user, string message)
        {
            // Здесь мы вызываем метод "ReceiveMessage" у ВСЕХ подключенных клиентов
            // Клиенты должны иметь метод или обработчик с именем "ReceiveMessage"
            Console.WriteLine($"User '{user}' sent message: {message}"); // Логирование на сервере
            await Clients.All.SendAsync("ReceiveMessage", user, message); 
        }

        // --- Пример метода, который может вызвать только вызвавший клиент ---
        public async Task RequestMatchmaking(string gameMode)
        {
             Console.WriteLine($"Client {Context.ConnectionId} requested matchmaking for {gameMode}");
             // Какая-то логика подбора игры...
             
             // Отправляем подтверждение обратно ТОЛЬКО этому клиенту
             await Clients.Caller.SendAsync("MatchmakingRequestReceived", gameMode, "Searching..."); 
        }


        // --- Переопределение системных методов Hub ---

        // Вызывается, когда новый клиент подключается к хабу
        public override async Task OnConnectedAsync()
        {
            Console.WriteLine($"Client connected: {Context.ConnectionId}");
            // Можно уведомить других или самого клиента
            // await Clients.Caller.SendAsync("Welcome", "Welcome to the Master Server!");
            // await Clients.Others.SendAsync("UserConnected", Context.ConnectionId); // Уведомить других
            await base.OnConnectedAsync();
        }

        // Вызывается, когда клиент отключается (штатно или из-за ошибки/таймаута)
        public override async Task OnDisconnectedAsync(Exception? exception)
        {
            Console.WriteLine($"Client disconnected: {Context.ConnectionId}");
            if (exception != null) {
                 Console.WriteLine($"   Reason: {exception.Message}");
            }
            // Можно уведомить других
            // await Clients.Others.SendAsync("UserDisconnected", Context.ConnectionId);
            await base.OnDisconnectedAsync(exception);
        }
    }
}