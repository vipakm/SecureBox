using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SecureBox.Data;
using SecureBox.Models;
using SecureBox.Services;
using SecureBox.Services.Interface;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

[Route("api/auth")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly OtpService _otpService;
    private readonly IEmailService _emailService;

    public AuthController(AppDbContext context, OtpService otpService, IEmailService emailService)
    {
        _context = context;
        _otpService = otpService;
        _emailService = emailService;
    }

    // ✅ 1. REGISTER USER & SEND OTP
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] UserDetail user)
    {
        if (await _context.UserDetails.AnyAsync(u => u.UserMailId == user.UserMailId))
            return BadRequest(new { message = "Email already exists" });

        // Generate OTP
        int otp = _otpService.GenerateOtp(user.UserMailId);

        // HTML Email Content for OTP Verification
        string subject = "SecureBox - OTP Verification";
        string body = $@"
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }}
                .container {{ max-width: 600px; background: #ffffff; margin: 20px auto; padding: 20px; border-radius: 8px; box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.1); }}
                .header {{ background: #007bff; color: #ffffff; text-align: center; padding: 15px; border-radius: 8px 8px 0 0; font-size: 24px; font-weight: bold; }}
                .content {{ padding: 20px; color: #333333; font-size: 16px; line-height: 1.6; }}
                .otp-code {{ font-size: 24px; font-weight: bold; color: #007bff; text-align: center; padding: 15px; border: 2px dashed #007bff; background: #f9f9f9; border-radius: 8px; }}
                .footer {{ text-align: center; font-size: 14px; color: #888888; margin-top: 20px; padding: 10px; border-top: 1px solid #dddddd; }}
            </style>
        </head>
        <body>
            <div class='container'>
                <div class='header'>SecureBox - OTP Verification</div>
                <div class='content'>
                    <p>Dear <strong>{user.UserName}</strong>,</p>
                    <p>Welcome to SecureBox! To complete your registration, please use the OTP below:</p>
                    <p class='otp-code'>{otp}</p>
                    <p>This OTP is valid for the next 10 minutes. Do not share this code with anyone.</p>
                    <p>If you did not request this, please ignore this email.</p>
                </div>
                <div class='footer'>© 2025 EbonCore Nexus Technologies. All rights reserved.</div>
            </div>
        </body>
        </html>";

        await _emailService.SendEmailAsync(user.UserMailId, subject, body);

        // Hash Password
        user.UserPassword = BCrypt.Net.BCrypt.HashPassword(user.UserPassword);
        user.UserStatus = false; // Set status false until OTP verified
        user.UserId = (await _context.UserDetails.MaxAsync(u => (int?)u.UserId) ?? 0) + 1;

        _context.UserDetails.Add(user);
        await _context.SaveChangesAsync();

        return Ok(new { message = "User registered! OTP sent to email." });
    }

    // ✅ 2. VERIFY OTP & ACTIVATE ACCOUNT
    [HttpPost("verify-otp")]
    public async Task<IActionResult> VerifyOtp(string email, int otp)
    {
        var user = await _context.UserDetails.FirstOrDefaultAsync(u => u.UserMailId == email);
        if (user == null)
            return NotFound(new { message = "User not found!" });

        if (!_otpService.ValidateOtp(email, otp))
            return BadRequest(new { message = "Invalid OTP!" });

        user.UserStatus = true; // Activate user
        await _context.SaveChangesAsync();

        // Send Welcome Email
        string subject = "Welcome to SecureBox!";
        string body = $@"
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }}
                .container {{ max-width: 600px; background: #ffffff; margin: 20px auto; padding: 20px; border-radius: 8px; box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.1); }}
                .header {{ background: #007bff; color: #ffffff; text-align: center; padding: 15px; border-radius: 8px 8px 0 0; font-size: 24px; font-weight: bold; }}
                .content {{ padding: 20px; color: #333333; font-size: 16px; line-height: 1.6; }}
                .footer {{ text-align: center; font-size: 14px; color: #888888; margin-top: 20px; padding: 10px; border-top: 1px solid #dddddd; }}
                .button {{ display: inline-block; background: #007bff; color: #ffffff; text-decoration: none; padding: 10px 20px; border-radius: 5px; margin-top: 15px; font-size: 16px; font-weight: bold; }}
                .button:hover {{ background: #0056b3; }}
            </style>
        </head>
        <body>
            <div class='container'>
                <div class='header'>Welcome to SecureBox!</div>
                <div class='content'>
                    <p>Dear <strong>{user.UserName}</strong>,</p>
                    <p>Thank you for choosing <strong>SecureBox</strong>! We are excited to have you onboard. Your account has been successfully activated.</p>
                    <p>Your password is securely encrypted, and we prioritize keeping your information safe. With SecureBox, your data is in safe hands, and you can rest assured that your sensitive information is protected.</p>
                    <p>If you ever need help with your account or have any questions, feel free to reach out to us at <a href='mailto:support@ecntech.in'>support@ecntech.in</a>.</p>
                    <p>© 2025 EbonCore Nexus Technologies. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>";

        await _emailService.SendEmailAsync(email, subject, body);

        return Ok(new { message = "OTP Verified! Account Activated. A confirmation email has been sent." });
    }


    // ✅ 3. LOGIN & GET JWT TOKEN
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest model)
    {
        var user = await _context.UserDetails.FirstOrDefaultAsync(u => u.UserMailId == model.Email);
        if (user == null || !BCrypt.Net.BCrypt.Verify(model.Password, user.UserPassword))
            return Unauthorized(new { message = "Invalid email or password" });

        if (user.UserStatus == false)
            return BadRequest(new { message = "Account not activated. Verify OTP first!" });

        // Generate JWT Token
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes("asdf7410asdf7410asdf7410asdf7410asdf7410"); // 🔑 Secure this key!
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
            new Claim("id", user.UserId.ToString()),
            new Claim("email", user.UserMailId)
        }),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);

        return Ok(new
        {
            token = tokenHandler.WriteToken(token),
            userId = user.UserId  // Send UserId along with the token
        });
    }


    // ✅ 4. FORGOT PASSWORD (SEND OTP)
    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword(string email)
    {
        var user = await _context.UserDetails.FirstOrDefaultAsync(u => u.UserMailId == email);
        if (user == null)
            return NotFound(new { message = "User not found!" });

        int otp = _otpService.GenerateOtp(email);

        // Email Content
        string subject = "SecureBox - Password Reset OTP";
        string body = $@"
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }}
                .container {{ max-width: 600px; background: #ffffff; margin: 20px auto; padding: 20px; border-radius: 8px; box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.1); }}
                .header {{ background: #007bff; color: #ffffff; text-align: center; padding: 15px; border-radius: 8px 8px 0 0; font-size: 24px; font-weight: bold; }}
                .content {{ padding: 20px; color: #333333; font-size: 16px; line-height: 1.6; }}
                .otp {{ font-size: 22px; font-weight: bold; color: #007bff; text-align: center; padding: 10px; border: 1px dashed #007bff; background: #f9f9f9; width: fit-content; margin: 15px auto; }}
                .footer {{ text-align: center; font-size: 14px; color: #888888; margin-top: 20px; padding: 10px; border-top: 1px solid #dddddd; }}
            </style>
        </head>
        <body>
            <div class='container'>
                <div class='header'>SecureBox - Password Reset</div>
                <div class='content'>
                    <p>Dear <strong>{user.UserName}</strong>,</p>
                    <p>We received a request to reset your password. Use the OTP below to proceed with resetting your password.</p>
                    <div class='otp'>{otp}</div>
                    <p>This OTP is valid for 10 minutes. If you did not request this, please ignore this email.</p>
                    <p>For any issues, contact our support team at <a href='mailto:support@ecntech.in'>support@ecntech.in</a>.</p>
                </div>
                <div class='footer'>© 2025 EbonCore Nexus Technologies. All rights reserved.</div>
            </div>
        </body>
        </html>";

        await _emailService.SendEmailAsync(email, subject, body);

        return Ok(new { message = "OTP sent to email for password reset." });
    }


    // ✅ 5. RESET PASSWORD (WITH OTP)
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest model)
    {
        var user = await _context.UserDetails.FirstOrDefaultAsync(u => u.UserMailId == model.Email);
        if (user == null)
            return NotFound(new { message = "User not found!" });

        if (!_otpService.ValidateOtp(model.Email, model.Otp))
            return BadRequest(new { message = "Invalid OTP!" });

        // Update the user's password
        user.UserPassword = BCrypt.Net.BCrypt.HashPassword(model.NewPassword);
        await _context.SaveChangesAsync();

        // Email Content
        string subject = "SecureBox - Password Reset Successful";
        string body = $@"
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }}
                .container {{ max-width: 600px; background: #ffffff; margin: 20px auto; padding: 20px; border-radius: 8px; box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.1); }}
                .header {{ background: #007bff; color: #ffffff; text-align: center; padding: 15px; border-radius: 8px 8px 0 0; font-size: 24px; font-weight: bold; }}
                .content {{ padding: 20px; color: #333333; font-size: 16px; line-height: 1.6; }}
                .footer {{ text-align: center; font-size: 14px; color: #888888; margin-top: 20px; padding: 10px; border-top: 1px solid #dddddd; }}
            </style>
        </head>
        <body>
            <div class='container'>
                <div class='header'>SecureBox - Password Reset Successful</div>
                <div class='content'>
                    <p>Dear <strong>{user.UserName}</strong>,</p>
                    <p>Your password has been successfully reset. You can now log in with your new password.</p>
                    <p>If you did not request this change, please contact our support team immediately.</p>
                    <p>For any issues, reach out to us at <a href='mailto:support@ecntech.in'>support@ecntech.in</a>.</p>
                </div>
                <div class='footer'>© 2025 EbonCore Nexus Technologies. All rights reserved.</div>
            </div>
        </body>
        </html>";

        await _emailService.SendEmailAsync(model.Email, subject, body);

        return Ok(new { message = "Password reset successful! A confirmation email has been sent." });
    }

}

// LOGIN MODEL
public class LoginRequest
{
    public string Email { get; set; }
    public string Password { get; set; }
}

// RESET PASSWORD MODEL
public class ResetPasswordRequest
{
    public string Email { get; set; }
    public int Otp { get; set; }
    public string NewPassword { get; set; }
}
