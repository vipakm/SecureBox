using SecureBox.Services.Interface;
using System;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace SecureBox.Services.Implementation
{
    public class EmailService : IEmailService
    {
        private readonly string smtpServer = "mail.ecntech.in"; // Titan SMTP server
        private readonly int smtpPort = 587; // Port for TLS encryption
        private readonly string email = "SecureBox@ecntech.in"; // Your Titan email
        private readonly string password = "3P3f79k*e"; // Your email password

        public async Task SendEmailAsync(string recipient, string subject, string body)
        {
            using (var client = new SmtpClient(smtpServer, smtpPort))
            {
                client.Credentials = new NetworkCredential(email, password); // Use correct credentials
                client.EnableSsl = true; // Enable secure connection

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(email, "EcnTech Support"), // Sender's email and display name
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = true // Enable HTML emails
                };

                mailMessage.To.Add(recipient); // Add recipient email
                mailMessage.Bcc.Add(email); // Add sender's email to BCC for a copy in your inbox

                try
                {
                    await client.SendMailAsync(mailMessage); // Send the email
                }
                catch (SmtpException ex)
                {
                    // Log or handle errors
                    throw new Exception("Failed to send email: " + ex.Message);
                }
            }
        }
    }
}
