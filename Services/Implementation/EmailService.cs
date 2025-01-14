using SecureBox.Services.Interface;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace SecureBox.Services.Implementation
{
    // Ensure EmailService implements IEmailService
    public class EmailService : IEmailService
    {
        private readonly string smtpServer = "mail.ecntech.in"; // Titan SMTP server
        private readonly int smtpPort = 587; // Port for SSL encryption
        private readonly string email = "SecureBox@ecntech.in"; // Your Titan email
        private readonly string password = "dn897F1i&"; // Normal password for the account

        public async Task SendEmailAsync(string recipient, string subject, string body)
        {
            using (var client = new SmtpClient(smtpServer, smtpPort))
            {
                // Using the same email address for authentication and sending
                client.Credentials = new NetworkCredential(email, password);
                // Use correct credentials
                client.EnableSsl = true; // Ensure secure connection

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(email, "EcnTech Support"), // Ensure the "From" address matches the authenticated email
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = true
                };

                mailMessage.To.Add(recipient);

                try
                {
                    await client.SendMailAsync(mailMessage);
                }
                catch (SmtpException ex)
                {
                    throw new Exception("Failed to send email: " + ex.Message);
                }
            }
        }

    }
}
