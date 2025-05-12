using MasterServer.Configuration;
using MasterServer.Services.Abstractions;
using Microsoft.Extensions.Options;
using MailKit.Net.Smtp;
using MailKit.Security; // Для SecureSocketOptions
using MimeKit;
using MimeKit.Text; // Для TextPart
using System;
using System.Threading.Tasks;

namespace MasterServer.Services.Implementations
{
    public class SmtpEmailService : IEmailService
    {
        private readonly SmtpSettings _smtpSettings;
        private readonly ILogger<SmtpEmailService> _logger;

        public SmtpEmailService(IOptions<SmtpSettings> smtpSettingsOptions, ILogger<SmtpEmailService> logger)
        {
            _smtpSettings = smtpSettingsOptions.Value;
            _logger = logger;
        }

        public async Task SendEmailAsync(string toEmail, string subject, string htmlBody)
        {
            try
            {
                var email = new MimeMessage();
                email.From.Add(new MailboxAddress(_smtpSettings.SenderName, _smtpSettings.SenderEmail));
                email.To.Add(MailboxAddress.Parse(toEmail));
                email.Subject = subject;
                email.Body = new TextPart(TextFormat.Html) { Text = htmlBody };

                using var smtp = new SmtpClient();

                _logger.LogInformation("Connecting to SMTP server {Host}:{Port}", _smtpSettings.Host, _smtpSettings.Port);

                // Для порта 587 (STARTTLS) используй SecureSocketOptions.StartTls
                // Для порта 465 (SSL/TLS) используй SecureSocketOptions.SslOnConnect
                SecureSocketOptions socketOptions = _smtpSettings.Port == 465
                                                    ? SecureSocketOptions.SslOnConnect
                                                    : SecureSocketOptions.StartTls;
                
                await smtp.ConnectAsync(_smtpSettings.Host, _smtpSettings.Port, socketOptions);
                
                // Примечание: Gmail может требовать OAuth2 для более новых приложений,
                // но пароли приложений все еще должны работать для SMTP.
                _logger.LogInformation("Authenticating with SMTP server using username {Username}", _smtpSettings.Username);
                await smtp.AuthenticateAsync(_smtpSettings.Username, _smtpSettings.Password);
                
                _logger.LogInformation("Sending email to {ToEmail} with subject '{Subject}'", toEmail, subject);
                await smtp.SendAsync(email);
                
                _logger.LogInformation("Email sent successfully to {ToEmail}", toEmail);
                await smtp.DisconnectAsync(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while sending email to {ToEmail} via SMTP.", toEmail);
                // throw; // Раскомментируй, если хочешь, чтобы ошибка пробрасывалась выше
            }
        }
    }
}