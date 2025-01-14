using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureBox.Models;
using SecureBox.Services.Interface;

namespace SecureBox.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly IUserService _userService;

        public UsersController(IUserService userService)
        {
            _userService = userService;
        }

        // Register User
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] User model)
        {
            if (model == null)
            {
                return BadRequest("Invalid user details.");
            }

            // Validate phone number if provided (non-nullable int)
            if (model.UserPhoneNo.HasValue && model.UserPhoneNo.Value == 0)
            {
                return BadRequest("Invalid phone number.");
            }

            // Convert UserPhoneNo (long?) to int, ensuring no overflow



            var result = await _userService.RegisterAsync(model.UserName, model.UserMailId, model.UserPhoneNo, model.UserPassword);
            if (result == "User already exists")
            {
                return BadRequest(new { message = result, code = 400 });
            }

            return Ok(new { message = "User registered successfully", code = 200 });
        }

        // Login User
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDetails model)
        {
            if (model == null || string.IsNullOrWhiteSpace(model.Email) || string.IsNullOrWhiteSpace(model.Password))
            {
                return BadRequest("Invalid login credentials.");
            }

            var result = await _userService.LoginAsync(model.Email, model.Password);
            if (result == "Invalid credentials")
            {
                return Unauthorized(new { message = result, code = 401 });
            }

            return Ok(new { Token = result, message = "Login successful", code = 200 });
        }


        // Reset Password
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] Reset model)
        {
            if (model == null || string.IsNullOrWhiteSpace(model.UserMailId))
            {
                return BadRequest("Email is required for password reset.");
            }

            var result = await _userService.ResetPasswordAsync(model.UserMailId);
            return Ok(new { message = result, code = 200 });
        }

        // Verify OTP
        [HttpPost("verify-otp")]
        public IActionResult VerifyOtp([FromBody] string userOtp)
        {
            if (string.IsNullOrWhiteSpace(userOtp))
            {
                return BadRequest("OTP is required.");
            }

            var isOtpValid = _userService.VerifyOtp(userOtp);
            if (isOtpValid)
            {
                return Ok(new { message = "OTP verified successfully", code = 200 });
            }
            else
            {
                return BadRequest(new { message = "Invalid or expired OTP", code = 400 });
            }
        }

        [HttpPost("verifyUser")]
        public async Task<IActionResult> VerifyUserOtp([FromBody] VerifyOtpDto model)
        {
            if (model == null || string.IsNullOrWhiteSpace(model.UserMailId) || string.IsNullOrWhiteSpace(model.Otp))
            {
                return BadRequest("Invalid request. Please provide both UserMailId and OTP.");
            }

            var result = await _userService.VerifyOtpAsync(model.UserMailId, model.Otp);

            if (result == "OTP expired or invalid." || result == "OTP has expired." || result == "Invalid OTP.")
            {
                return BadRequest(new { message = result, code = 400 });
            }

            if (result == "User not found.")
            {
                return NotFound(new { message = result, code = 404 });
            }

            return Ok(new { message = result, code = 200 });
        }

        [HttpPut("update-password")]
        public async Task<IActionResult> UpdatePassword([FromBody] UpdatePasswordModel model)
        {
            if (model == null || string.IsNullOrWhiteSpace(model.UserMailId) || string.IsNullOrWhiteSpace(model.NewPassword))
            {
                return BadRequest("Invalid input data.");
            }

            // Call the service to update the password
            var result = await _userService.UpdatePasswordAsync(model.UserMailId, model.NewPassword);

            if (result == "User not found.")
            {
                return NotFound(new { message = result, code = 404 });
            }

            if (result == "Email not verified.")
            {
                return BadRequest(new { message = result, code = 400 });
            }

            return Ok(new { message = result, code = 200 });
        }


    }
    public class User
    {
        public string UserName { get; set; }

        public string UserMailId { get; set; }

        public long? UserPhoneNo { get; set; }

        public string UserPassword { get; set; }
    }
    public class VerifyOtpDto
    {
        public string UserMailId { get; set; }
        public string Otp { get; set; }
    }

    public class LoginDetails
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class Reset
    {
        public string UserMailId { get; set; }
    }

    public class UpdatePasswordModel
    {
        public string UserMailId { get; set; }
        public string NewPassword { get; set; }
    }


}
