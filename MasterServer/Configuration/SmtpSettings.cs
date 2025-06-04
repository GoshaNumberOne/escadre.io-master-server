namespace MasterServer.Configuration
{
    public class SmtpSettings
    {
        public required string Host { get; set; }
        public int Port { get; set; }
        public bool EnableSsl { get; set; } // Для Gmail это обычно true
        public required string Username { get; set; }
        public required string Password { get; set; }
        public required string SenderEmail { get; set; }
        public required string SenderName { get; set; }
    }
}