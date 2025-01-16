using Microsoft.IdentityModel.Tokens;
using SecureBox.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using BCrypt.Net;
using Microsoft.EntityFrameworkCore;
using SecureBox.Data;
using SecureBox.Services.Interface;
using SecureBox.ViewModels;
using System;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;

namespace SecureBox.Services
{
    public class UserService : IUserService
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public UserService(AppDbContext context, IConfiguration configuration, IEmailService emailService, IHttpContextAccessor httpContextAccessor)
        {
            _context = context;
            _configuration = configuration;
            _emailService = emailService;
            _httpContextAccessor = httpContextAccessor;
        }
        // Registration Method
        public async Task<string> RegisterAsync(string userName, string userMailId, long? userPhoneNo, string userPassword)
        {
            // Check if the email already exists in the database
            var userExists = await _context.UserDetails.FirstOrDefaultAsync(u => u.UserMailId == userMailId);
            if (userExists != null)
            {
                return "User already exists";
            }

            // Validate phone number (ensure no 0)
            if (userPhoneNo.HasValue && userPhoneNo.Value == 0)
            {
                return "Invalid phone number.";
            }

            // Generate OTP and send to user via email
            var otp = new Random().Next(1000, 9999).ToString();
            var subject = "OTP for User Registration";

            // Store OTP and expiry time in session
            _httpContextAccessor.HttpContext.Session.SetString("OTP", otp);
            _httpContextAccessor.HttpContext.Session.SetString("OTPExpiry", DateTime.Now.AddMinutes(10).ToString());

            // Beautiful Email HTML body
            string htmlBody = $@"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>{subject}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #f9f9f9;
            margin: 0;
            padding: 0;
        }}
        .container {{
            width: 100%;
            max-width: 600px;
            margin: 0 auto;
            background: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
        h1 {{
            color: #333;
            text-align: center;
            font-size: 24px;
        }}
        p {{
            font-size: 16px;
            line-height: 1.5;
            margin: 10px 0;
        }}
        .otp {{
            font-size: 20px;
            font-weight: bold;
            color: #007bff;
            padding: 10px;
            border: 1px solid #007bff;
            border-radius: 5px;
            text-align: center;
            margin: 20px 0;
        }}
        .footer {{
            text-align: center;
            font-size: 12px;
            color: #888;
            margin-top: 30px;
        }}
        .footer a {{
            color: #007bff;
            text-decoration: none;
        }}
    </style>
</head>
<body>
    <div class='container'>
        <h1>Welcome to SecureBox, {userName}!</h1>
        <p>Thank you for registering with SecureBox. We are excited to have you onboard.</p>
        <p>Your One-Time Password (OTP) for completing the registration process is:</p>
        <div class='otp'>{otp}</div>
        <p>This OTP is valid for 10 minutes, so please use it to complete your registration within the given time frame.</p>
        <p>If you did not request this registration, please ignore this email or contact our support team.</p>
        <div class='footer'>
            <p>&copy; {DateTime.Now.Year} EbonCore Nexus Technologies. All rights reserved.</p>
            <p>If you need assistance, contact us at <a href='mailto:support@ecntech.in'>support@ecntech.in</a></p>
        </div>
    </div>
</body>
</html>";

            // Send OTP email asynchronously
            await _emailService.SendEmailAsync(userMailId, subject, htmlBody);

            // Generate the next UserId (max + 1) or set to 1 if the table is empty
            var maxUserId = await _context.UserDetails.MaxAsync(u => (int?)u.UserId) ?? 0;
            var nextUserId = maxUserId + 1;

            // Hash the password using bcrypt
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(userPassword);

            // Save user information with UserStatus = false
            var newUser = new UserDetail
            {
                UserId = nextUserId,
                UserName = userName,
                UserMailId = userMailId,
                UserPhoneNo = userPhoneNo,
                UserPassword = hashedPassword, // Store the hashed password
                UserStatus = false,
            };

            await _context.UserDetails.AddAsync(newUser);
            await _context.SaveChangesAsync();

            return "OTP sent to your email. Please verify to complete registration.";
        }

        // OTP Verification Method
        public async Task<string> VerifyOtpAsync(string userMailId, string inputOtp)
        {
            // Get the stored OTP and expiry time from session
            var storedOtp = _httpContextAccessor.HttpContext.Session.GetString("OTP");
            var expiryTime = _httpContextAccessor.HttpContext.Session.GetString("OTPExpiry");

            if (string.IsNullOrEmpty(storedOtp) || string.IsNullOrEmpty(expiryTime))
            {
                return "OTP expired or invalid.";
            }

            if (DateTime.Now > DateTime.Parse(expiryTime))
            {
                return "OTP has expired.";
            }

            if (storedOtp != inputOtp)
            {
                return "Invalid OTP.";
            }

            // Activate the user in the database
            var user = await _context.UserDetails.FirstOrDefaultAsync(u => u.UserMailId == userMailId);
            if (user == null)
            {
                return "User not found.";
            }

            user.UserStatus = true;
            _context.UserDetails.Update(user);
            await _context.SaveChangesAsync();

            // Clear the OTP session after successful verification
            _httpContextAccessor.HttpContext.Session.Remove("OTP");
            _httpContextAccessor.HttpContext.Session.Remove("OTPExpiry");

            // Send a thank-you email for choosing SecureBox
            var subject = "Thank You for Choosing SecureBox!";
            string htmlBody = $@"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>{subject}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #f9f9f9;
            margin: 0;
            padding: 0;
        }}
        .container {{
            width: 100%;
            max-width: 600px;
            margin: 0 auto;
            background: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
        h1 {{
            color: #333;
            text-align: center;
            font-size: 24px;
        }}
        p {{
            font-size: 16px;
            line-height: 1.5;
            margin: 10px 0;
        }}
        .footer {{
            text-align: center;
            font-size: 12px;
            color: #888;
            margin-top: 30px;
        }}
        .footer a {{
            color: #007bff;
            text-decoration: none;
        }}
    </style>
</head>
<body>
    <div class='container'>
        <h1>Welcome to SecureBox!</h1>
        <p>Dear {user.UserName},</p>
        <p>Thank you for choosing SecureBox! We are excited to have you onboard. Your account has been successfully activated.</p>
        <p>Your password is securely encrypted, and we prioritize keeping your information safe. With SecureBox, your data is in safe hands, and you can rest assured that your sensitive information is protected.</p>
        <p>If you ever need help with your account or have any questions, feel free to reach out to us at <a href='mailto:support@ecntech.in'>support@ecntech.in</a>.</p>
        <div class='footer'>
            <p>&copy; {DateTime.Now.Year} EbonCore Nexus Technologies. All rights reserved.</p>
        </div>
    </div>
</body>
</html>";

            // Send the thank you email asynchronously
            await _emailService.SendEmailAsync(userMailId, subject, htmlBody);

            return "Your account has been successfully activated. A confirmation email has been sent to your inbox.";
        }

        // Login User
        public async Task<LoginResult> LoginAsync(string email, string password)
        {
            var user = await _context.UserDetails.FirstOrDefaultAsync(u => u.UserMailId == email);
            if (user == null || !BCrypt.Net.BCrypt.Verify(password, user.UserPassword))
            {
                return new LoginResult
                {
                    Success = false,
                    Message = "Invalid credentials",
                    Code = 401
                };
            }

            var token = GenerateJwtToken(user);
            return new LoginResult
            {
                Success = true,
                Token = token,
                UserId = user.UserId,
                Message = "Login successful",
                Code = 200
            };
        }



        // Reset Password (OTP generation and email)
        public async Task<string> ResetPasswordAsync(string email)
        {
            var user = await _context.UserDetails.FirstOrDefaultAsync(u => u.UserMailId == email);
            if (user == null)
            {
                return "User not found";
            }

            var otp = new Random().Next(1000, 9999).ToString();
            var subject = "OTP for Password Reset";

            // Store the OTP in the session
            _httpContextAccessor.HttpContext.Session.SetString("OTP", otp);
            _httpContextAccessor.HttpContext.Session.SetString("OTPExpiry", DateTime.Now.AddMinutes(10).ToString());

            // Define the HTML body of the email
            string htmlBody = $@"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>{subject}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f4f4f9;
            color: #333;
        }}
        .container {{
            width: 100%;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #333;
            font-size: 24px;
        }}
        .content {{
            font-size: 16px;
            line-height: 1.5;
            margin-bottom: 20px;
        }}
        .otp {{
            font-size: 22px;
            font-weight: bold;
            color: #4caf50;
            text-align: center;
            margin-bottom: 20px;
        }}
        .footer {{
            font-size: 12px;
            color: #888;
            text-align: center;
            margin-top: 20px;
        }}
        .footer a {{
            color: #4caf50;
            text-decoration: none;
        }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>Password Reset Request</h1>
        </div>
        <div class='content'>
            <p>Hello {user.UserName},</p>
            <p>We received a request to reset the password for your SecureBox account. To complete the process, please use the OTP below:</p>
            <div class='otp'>
                {otp}
            </div>
            <p>The OTP is valid for 10 minutes. If you did not request a password reset, please ignore this email.</p>
            <p>Thank you for using SecureBox!</p>
        </div>
        <div class='footer'>
            <p>If you have any questions, please contact our support team at <a href='mailto:support@securebox.com'>support@securebox.com</a>.</p>
            <p>SecureBox | All rights reserved</p>
        </div>
    </div>
</body>
</html>";

            // Send the email asynchronously with the HTML body
            await _emailService.SendEmailAsync(user.UserMailId, subject, htmlBody);

            return "OTP sent to your email";
        }

        // Generate JWT token for authentication
        public string GenerateJwtToken(UserDetail user)
        {
            var claims = new[] {
        new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()), // User ID
        new Claim(ClaimTypes.Name, user.UserName),
        new Claim(ClaimTypes.Email, user.UserMailId),
    };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["JwtSettings:Issuer"],
                audience: _configuration["JwtSettings:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(Convert.ToDouble(_configuration["JwtSettings:ExpirationInMinutes"])),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


        public async Task<string> UpdatePasswordAsync(string userMailId, string newPassword)
        {
            // Find the user by email
            var user = await _context.UserDetails.FirstOrDefaultAsync(u => u.UserMailId == userMailId);
            if (user == null)
            {
                return "User not found.";
            }

            // Check if the email is verified (UserStatus is true)
            if ((bool)!user.UserStatus)
            {
                return "Email not verified.";
            }

            // Hash the new password
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(newPassword);

            // Update the user's password
            user.UserPassword = hashedPassword;
            _context.UserDetails.Update(user);
            await _context.SaveChangesAsync();

            // Send confirmation email
            var subject = "Password Reset Confirmation";
            string htmlBody = $@"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>{subject}</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; background-color: #f9f9f9; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff; border: 1px solid #ddd; border-radius: 8px; }}
        h1 {{ color: #007bff; text-align: center; }}
        p {{ margin: 10px 0; }}
        .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #777; }}
    </style>
</head>
<body>
    <div class='container'>
        <h1>Password Reset Successful</h1>
        <p>Hello <strong>{user.UserName}</strong>,</p>
        <p>We wanted to let you know that your password has been successfully reset for your SecureBox account. If you didn't request this change, please contact our support team immediately at <a href='mailto:support@ecntech.in'>support@ecntech.in</a>.</p>
        <p><strong>Thank you for using SecureBox!</strong></p>
        <div class='footer'>
            <p>&copy; {DateTime.Now.Year} EbonCore Nexus Technologies. All rights reserved.</p>
        </div>
    </div>
</body>
</html>";

            // Send email to the user
            await _emailService.SendEmailAsync(userMailId, subject, htmlBody);

            return "Password updated successfully. A confirmation email has been sent.";
        }


        // Verify OTP from session
        public bool VerifyOtp(string userOtp)
        {
            var otp = _httpContextAccessor.HttpContext.Session.GetString("OTP");
            var otpExpiry = _httpContextAccessor.HttpContext.Session.GetString("OTPExpiry");

            if (otp == null || otpExpiry == null)
            {
                return false; // OTP expired or not found
            }

            if (DateTime.TryParse(otpExpiry, out DateTime expiry) && DateTime.Now <= expiry)
            {
                return otp == userOtp;
            }
            else
            {
                return false; // OTP expired
            }
        }
    }
}
