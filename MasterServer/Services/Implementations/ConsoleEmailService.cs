using MasterServer.Services.Abstractions;

namespace MasterServer.Services.Implementations
{
    // TODO: заглушка
    public class ConsoleEmailService : IEmailService
    {
        public Task SendEmailAsync(string toEmail, string subject, string htmlBody)
        {
            Console.WriteLine("--- Sending Email ---");
            Console.WriteLine($"To: {toEmail}");
            Console.WriteLine($"Subject: {subject}");
            Console.WriteLine("Body (HTML):");
            Console.WriteLine(htmlBody);
            Console.WriteLine("--- Email End ---");

            return Task.CompletedTask;
        }
    }
}